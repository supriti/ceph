// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab ft=cpp

/*
 * Ceph - scalable distributed file system
 *
 * Copyright contributors to the Ceph project
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation. See file COPYING.
 *
 */

#include "rgw_single_flight.h"

#include <atomic>
#include <exception>
#include <latch>
#include <string>
#include <thread>
#include <vector>

#include <boost/asio/io_context.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/asio/steady_timer.hpp>
#include <gtest/gtest.h>

#include "include/expected.hpp"

using namespace std::chrono_literals;

namespace rgw {

static void rethrow(std::exception_ptr eptr)
{
  if (eptr) std::rethrow_exception(eptr);
}

using result_t = tl::expected<std::string, int>;
using flight_t = SingleFlight<result_t>;

/// Suspend the calling coroutine briefly, the way an HTTP request to Keystone
/// would, so that the other coroutines have time to queue up behind it.
static void suspend(boost::asio::yield_context yield)
{
  boost::asio::steady_timer timer(yield.get_executor(), 10ms);
  timer.async_wait(yield);
}

// A burst of coroutine callers for one key results in a single fetch, and every
// caller gets its result.
TEST(SingleFlight, CoalescesCoroutines)
{
  constexpr int callers = 50;
  boost::asio::io_context context;
  flight_t flight;
  std::atomic<int> fetches = 0;
  int fetched_count = 0;
  int adopted_count = 0;

  for (int i = 0; i < callers; i++) {
    boost::asio::spawn(context,
        [&] (boost::asio::yield_context yield) {
          auto outcome = flight.get("key", yield, [&] () -> result_t {
              fetches++;
              suspend(yield);
              return std::string("secret");
            });
          ASSERT_TRUE(outcome.result.has_value());
          EXPECT_EQ("secret", outcome.result.value());
          if (outcome.fetched) {
            fetched_count++;
          } else {
            adopted_count++;
          }
        }, rethrow);
  }
  context.run();

  EXPECT_EQ(1, fetches);
  EXPECT_EQ(1, fetched_count);
  EXPECT_EQ(callers - 1, adopted_count);
  EXPECT_EQ(0u, flight.size());
}

// Different keys are independent: no coalescing between them.
TEST(SingleFlight, DistinctKeysDoNotShare)
{
  constexpr int keys = 8;
  boost::asio::io_context context;
  flight_t flight;
  std::atomic<int> fetches = 0;

  for (int i = 0; i < keys; i++) {
    const auto key = std::to_string(i);
    boost::asio::spawn(context,
        [&, key] (boost::asio::yield_context yield) {
          auto outcome = flight.get(key, yield, [&] () -> result_t {
              fetches++;
              suspend(yield);
              return key;
            });
          ASSERT_TRUE(outcome.result.has_value());
          EXPECT_EQ(key, outcome.result.value());
          EXPECT_TRUE(outcome.fetched);
        }, rethrow);
  }
  context.run();

  EXPECT_EQ(keys, fetches);
  EXPECT_EQ(0u, flight.size());
}

// Callers that pass null_yield block their thread instead of suspending, and are
// coalesced the same way.
TEST(SingleFlight, CoalescesThreads)
{
  constexpr int callers = 16;
  flight_t flight;
  std::atomic<int> fetches = 0;
  std::atomic<int> fetched_count = 0;
  std::latch ready{callers};

  std::vector<std::thread> threads;
  for (int i = 0; i < callers; i++) {
    threads.emplace_back([&] {
        ready.arrive_and_wait();
        auto outcome = flight.get("key", null_yield, [&] () -> result_t {
            fetches++;
            // generous, so that a loaded machine still starts every thread
            // inside the window where the fetch is in flight
            std::this_thread::sleep_for(300ms);
            return std::string("secret");
          });
        ASSERT_TRUE(outcome.result.has_value());
        EXPECT_EQ("secret", outcome.result.value());
        if (outcome.fetched) {
          fetched_count++;
        }
      });
  }
  for (auto& t : threads) {
    t.join();
  }

  // threads may not all arrive within the fetch, so we can only require that
  // coalescing happened at all and that each fetch had exactly one leader
  EXPECT_LT(fetches, callers);
  EXPECT_EQ(fetches, fetched_count);
  EXPECT_EQ(0u, flight.size());
}

// outcome::fetched must describe what the caller actually did, not whether it
// created the registry entry. The caller that creates the entry can be overtaken
// between creating it and reaching call_once(), in which case it waits while the
// caller that overtook it does the fetch. Callers rely on this flag to tell a
// result they produced from one they adopted, so getting it backwards is not
// cosmetic.
// Counting fetches is not enough to check this: exactly one caller claims the
// fetch either way, so the totals balance even when the claim lands on the wrong
// caller. The property is per caller -- outcome.fetched is true for me if and
// only if my own fetch ran -- so each caller has to compare the two directly.
TEST(SingleFlight, FetchedReportsTheActualFetcher)
{
  flight_t flight;
  std::atomic<int> mismatches = 0;
  std::atomic<int> fetches = 0;

  constexpr int rounds = 200;
  constexpr int callers = 4;
  for (int round = 0; round < rounds; round++) {
    std::latch ready{callers};
    std::vector<std::thread> threads;
    for (int i = 0; i < callers; i++) {
      threads.emplace_back([&] {
          ready.arrive_and_wait();
          bool my_fetch_ran = false;
          auto outcome = flight.get("key", null_yield, [&] () -> result_t {
              my_fetch_ran = true;
              fetches++;
              std::this_thread::sleep_for(1ms);
              return std::string("secret");
            });
          ASSERT_TRUE(outcome.result.has_value());
          if (outcome.fetched != my_fetch_ran) {
            mismatches++;
          }
        });
    }
    for (auto& t : threads) {
      t.join();
    }
  }

  EXPECT_EQ(0, mismatches);
  EXPECT_LT(fetches, rounds * callers);   // coalescing did happen
  EXPECT_EQ(0u, flight.size());
}

// A failed fetch is shared with the waiters but not remembered: the next caller
// starts a new fetch. This is what lets a request that adopted somebody else's
// failure retry with a request of its own.
TEST(SingleFlight, FailureIsNotRemembered)
{
  boost::asio::io_context context;
  flight_t flight;
  std::atomic<int> fetches = 0;

  boost::asio::spawn(context,
      [&] (boost::asio::yield_context yield) {
        auto fetch = [&] () -> result_t {
          fetches++;
          suspend(yield);
          return tl::unexpected(-EACCES);
        };
        for (int attempt = 0; attempt < 3; attempt++) {
          auto outcome = flight.get("key", yield, fetch);
          ASSERT_FALSE(outcome.result.has_value());
          EXPECT_EQ(-EACCES, outcome.result.error());
          EXPECT_TRUE(outcome.fetched);
          EXPECT_EQ(0u, flight.size());
        }
      }, rethrow);
  context.run();

  EXPECT_EQ(3, fetches);
}

// An exception from the fetch reaches every caller, including one thrown by
// value as the rgw auth engines do, and leaves nothing behind. Before
// ceph::async::call_once() caught non-std exceptions, the waiters here were
// never woken and this test hung.
TEST(SingleFlight, ThrownIntReachesAllCallers)
{
  constexpr int callers = 8;
  boost::asio::io_context context;
  flight_t flight;
  std::atomic<int> fetches = 0;
  std::atomic<int> caught = 0;

  for (int i = 0; i < callers; i++) {
    boost::asio::spawn(context,
        [&] (boost::asio::yield_context yield) {
          try {
            flight.get("key", yield, [&] () -> result_t {
                fetches++;
                suspend(yield);
                throw -EIO;
              });
            FAIL() << "expected the fetch to throw";
          } catch (const int err) {
            EXPECT_EQ(-EIO, err);
            caught++;
          }
        }, rethrow);
  }
  context.run();

  EXPECT_EQ(1, fetches);
  EXPECT_EQ(callers, caught);
  EXPECT_EQ(0u, flight.size());
}

// Callers arriving after a fetch completed do not adopt its result; the entry is
// gone, so they fetch again. Coalescing covers requests that overlap in time,
// and remembering results is the surrounding cache's job.
TEST(SingleFlight, SequentialCallersRefetch)
{
  boost::asio::io_context context;
  flight_t flight;
  std::atomic<int> fetches = 0;

  boost::asio::spawn(context,
      [&] (boost::asio::yield_context yield) {
        for (int i = 0; i < 3; i++) {
          auto outcome = flight.get("key", yield, [&] () -> result_t {
              fetches++;
              return std::string("secret");
            });
          ASSERT_TRUE(outcome.result.has_value());
          EXPECT_TRUE(outcome.fetched);
        }
      }, rethrow);
  context.run();

  EXPECT_EQ(3, fetches);
}

} // namespace rgw

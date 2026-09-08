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

#pragma once

#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <utility>

#include "common/async/call_once.h"
#include "common/async/yield_context.h"

namespace rgw {

/// Cache stampede (thundering herd) mitigation for keyed lookups.
///
/// Deduplicates concurrent fetches of the same key: the first caller performs
/// the fetch while the others wait for its result. Coroutine callers are
/// suspended rather than blocking their thread; null_yield callers block.
///
/// This tracks only requests that are in flight; storing the result is left to
/// the caller, so it can be combined with an existing cache:
///
///   if (auto val = cache.find(key); val) {
///     return *val;
///   }
///   auto [result, fetched] = flight.get(key, y, [&] {
///       auto r = do_fetch(key);
///       if (r) {
///         cache.add(key, *r);   // publish before the waiters wake
///       }
///       return r;
///     });
///
/// Entries are removed once the fetch completes, so failures are never
/// remembered; the next caller starts a new fetch.
///
/// Result must be copyable and default-constructible.
template <typename Result>
class SingleFlight {
 public:
  struct outcome {
    Result result;
    /// True if this caller performed the fetch, false if it adopted the result
    /// of a fetch started by another caller.
    bool fetched = false;
  };

  /// Return the result of fetch() for the given key, performing it exactly once
  /// across all callers that overlap in time.
  outcome get(const std::string& key, optional_yield y,
              const std::function<Result()>& fetch)
  {
    std::shared_ptr<once_result> once;
    {
      // the lookup and the insert have to be one atomic step, or two callers
      // both decide that nothing is in flight
      std::lock_guard l{mutex};
      auto& value = in_flight_map[key];
      if (!value) {
        value = std::make_shared<once_result>();
      }
      // our own reference, so the state outlives its map entry
      once = value;
    }

    // call_once() runs the fetch of whichever caller finds the state
    // uninitialized, which is not necessarily the one that created the entry.
    // Recording this from inside the fetch is the only place it cannot be wrong.
    bool fetched = false;
    auto fetch_and_record = [&] {
      fetched = true;
      return fetch();
    };

    // mutex deliberately not held: it would serialise every key behind one
    // round trip
    try {
      auto result = call_once(*once, y, fetch_and_record);
      erase(key, once);
      return {std::move(result), fetched};
    } catch (...) {
      erase(key, once);
      throw;
    }
  }

  /// Number of fetches currently in flight. For tests and debugging.
  size_t size() const
  {
    std::lock_guard l{mutex};
    return in_flight_map.size();
  }

 private:
  using once_result = ceph::async::once_result<Result>;

  /// Remove the entry for key if it still refers to the given shared state.
  /// The identity check matters: without it a straggler from one generation
  /// would delete the entry the next generation has already installed.
  void erase(const std::string& key, const std::shared_ptr<once_result>& once)
  {
    std::lock_guard l{mutex};
    if (auto iter = in_flight_map.find(key);
        iter != in_flight_map.end() && iter->second == once) {
      in_flight_map.erase(iter);
    }
  }

  mutable std::mutex mutex;
  std::map<std::string, std::shared_ptr<once_result>> in_flight_map;
};

} // namespace rgw

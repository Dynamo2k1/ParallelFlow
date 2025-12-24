#pragma once
#include <algorithm>
#include <cstdint>
#include <unordered_map>
#include <vector>

// Space-Saving heavy hitter algorithm (approx top-K).
template <typename Key, typename CountT = uint64_t>
class SpaceSaving {
public:
  explicit SpaceSaving(size_t capacity = 50) : cap_(capacity) {}

  void set_capacity(size_t cap) { cap_ = cap; prune(); }

  void add(const Key& k, CountT w = 1) {
    if (cap_ == 0) return;
    auto it = idx_.find(k);
    if (it != idx_.end()) {
      items_[it->second].count += w;
      return;
    }
    if (items_.size() < cap_) {
      items_.push_back(Item{k, w, 0});
      idx_[k] = items_.size() - 1;
      return;
    }
    // replace minimum
    size_t min_i = 0;
    for (size_t i = 1; i < items_.size(); i++) {
      if (items_[i].count < items_[min_i].count) min_i = i;
    }
    idx_.erase(items_[min_i].key);
    CountT min_count = items_[min_i].count;
    items_[min_i] = Item{k, min_count + w, min_count}; // error = previous min
    idx_[k] = min_i;
  }

  struct Item { Key key; CountT count; CountT error; };

  std::vector<Item> top() const {
    auto v = items_;
    std::sort(v.begin(), v.end(), [](const Item& a, const Item& b){ return a.count > b.count; });
    return v;
  }

  size_t capacity() const { return cap_; }

private:
  void prune() {
    if (items_.size() <= cap_) return;
    auto v = top();
    v.resize(cap_);
    items_ = v;
    idx_.clear();
    for (size_t i = 0; i < items_.size(); i++) idx_[items_[i].key] = i;
  }

  size_t cap_;
  std::vector<Item> items_;
  std::unordered_map<Key, size_t> idx_;
};

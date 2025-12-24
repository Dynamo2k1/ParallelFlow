#pragma once
#include <array>
#include <cstdint>
#include <queue>
#include <string>
#include <unordered_map>
#include <vector>

// Byte-oriented Aho–Corasick automaton. Suitable for payload scanning.
// Complexity: O(text_len + matches).

class AhoCorasick {
public:
  struct Match { int keyword_id; size_t end_pos; };

  void build(const std::vector<std::string>& keywords) {
    keywords_ = keywords;
    nodes_.clear();
    nodes_.push_back(Node{}); // root

    for (int i = 0; i < (int)keywords.size(); i++) {
      const auto& k = keywords[i];
      int v = 0;
      for (unsigned char ch : k) {
        int nxt = nodes_[v].next[ch];
        if (nxt == -1) {
          nxt = (int)nodes_.size();
          nodes_[v].next[ch] = nxt;
          nodes_.push_back(Node{});
        }
        v = nxt;
      }
      nodes_[v].out.push_back(i);
    }

    // build failure links
    std::queue<int> q;
    nodes_[0].link = 0;
    for (int c = 0; c < 256; c++) {
      int u = nodes_[0].next[c];
      if (u != -1) {
        nodes_[u].link = 0;
        q.push(u);
      } else {
        nodes_[0].next[c] = 0; // speed: fallback to root
      }
    }

    while (!q.empty()) {
      int v = q.front(); q.pop();
      int link = nodes_[v].link;
      for (int c = 0; c < 256; c++) {
        int u = nodes_[v].next[c];
        if (u != -1) {
          nodes_[u].link = nodes_[link].next[c];
          // merge outputs
          auto& out_u = nodes_[u].out;
          const auto& out_link = nodes_[nodes_[u].link].out;
          out_u.insert(out_u.end(), out_link.begin(), out_link.end());
          q.push(u);
        } else {
          nodes_[v].next[c] = nodes_[link].next[c];
        }
      }
    }
    built_ = true;
  }

  bool built() const { return built_; }
  const std::vector<std::string>& keywords() const { return keywords_; }

  // Returns matches (keyword id and end position in text). If you only need "did match",
  // you can stop early after first match.
  template <typename BytePtr>
  std::vector<Match> search(BytePtr data, size_t n, size_t max_matches = 0) const {
    std::vector<Match> m;
    if (!built_) return m;
    int v = 0;
    for (size_t i = 0; i < n; i++) {
      unsigned char c = (unsigned char)data[i];
      v = nodes_[v].next[c];
      for (int id : nodes_[v].out) {
        m.push_back(Match{id, i});
        if (max_matches > 0 && m.size() >= max_matches) return m;
      }
    }
    return m;
  }

private:
  struct Node {
    std::array<int, 256> next;
    int link = 0;
    std::vector<int> out;
    Node() {
      next.fill(-1);
    }
  };

  bool built_ = false;
  std::vector<std::string> keywords_;
  std::vector<Node> nodes_;
};

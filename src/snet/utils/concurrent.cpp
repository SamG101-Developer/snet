module;

#define LOCK_UNIQUE                                \
    std::unique_lock lock(get_mutex(key));  \
    auto index = m_hasher(key) % m_buckets.size(); \
    auto &bucket = m_buckets[index]

#define LOCK_SHARED                                \
    std::shared_lock lock(get_mutex(key));  \
    auto index = m_hasher(key) % m_buckets.size(); \
    auto &bucket = m_buckets[index]


export module snet.utils.concurrent;
import genex;
import std;

namespace snet::utils {
    export template <typename K, typename V, typename Hash = std::hash<K>>
    class ConcurrentHashMap;
}


template <typename K, typename V, typename Hash>
class snet::utils::ConcurrentHashMap {
    struct Node {
        K key;
        V val;
    };

    std::vector<std::list<Node>> m_buckets;
    mutable std::vector<std::shared_mutex> m_mutexes;
    Hash m_hasher;

    auto get_mutex(K const &key) const -> std::shared_mutex& {
        auto hash = m_hasher(key);
        return m_mutexes[hash % m_mutexes.size()];
    }

public:
    explicit ConcurrentHashMap(const std::size_t bucket_count = 16uz) :
        m_buckets(std::max(1uz, bucket_count)),
        m_mutexes(std::max(1uz, bucket_count)) {
    }

    ConcurrentHashMap(ConcurrentHashMap const &other) :
        m_buckets(other.m_buckets.size()),
        m_mutexes(other.m_mutexes.size()),
        m_hasher(other.m_hasher) {
        for (std::size_t i = 0; i < other.m_buckets.size(); ++i) {
            std::shared_lock lock(other.m_mutexes[i]);
            m_buckets[i] = other.m_buckets[i];
        }
    }

    ~ConcurrentHashMap() = default;

    auto insert(K const &key, V const &val) -> void {
        LOCK_UNIQUE;
        auto it = genex::find_if(
            bucket, genex::operations::eq_fixed(key), &Node::key);
        if (it == bucket.end()) { it->val = val; }
        else { bucket.emplace_back({key, val}); }
    }

    auto contains(K const &key) const -> bool {
        LOCK_SHARED;
        auto it = genex::find_if(
            bucket, genex::operations::eq_fixed(key), &Node::key);
        return it != bucket.end();
    }

    auto get(K const &key) const -> std::optional<V&> {
        LOCK_SHARED;
        auto it = genex::find_if(
            bucket, genex::operations::eq_fixed(key), &Node::key);
        return it == bucket.end() ? std::nullopt : std::optional<V&>(it->val);
    }

    auto erase(K const &key) -> bool {
        LOCK_UNIQUE;
        genex::actions::remove_if(
            bucket, genex::operations::eq_fixed(key), &Node::key);
        return true;
    }

    auto operator[](K const &key) -> V& {
        LOCK_UNIQUE;
        auto it = genex::find_if(
            bucket, genex::operations::eq_fixed(key), &Node::key);
        if (it == bucket.end()) {
            bucket.emplace_back(Node{key, V{}});
            return bucket.back().val;
        }
        return it->val;
    }

    auto operator[](K const& key) const -> V const& {
        LOCK_SHARED;
        auto it = genex::find_if(
            bucket, genex::operations::eq_fixed(key), &Node::key);
        if (it == bucket.end()) {
            throw std::out_of_range("Key not found in ConcurrentHashMap");
        }
        return it->val;
    }

    auto size() const -> std::size_t {
        std::size_t total_size = 0;
        for (std::size_t i = 0; i < m_buckets.size(); ++i) {
            std::shared_lock lock(m_mutexes[i]);
            total_size += m_buckets[i].size();
        }
        return total_size;
    }
};

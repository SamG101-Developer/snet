export module snet.crypt.bytes;
import openssl;
import std;


export namespace snet::crypt::bytes {
    template <typename T>
    struct SecureAllocator;

    /**
     * SecureVector is a custom vector type that uses SecureAllocator to ensure that the memory used for its elements
     * is allocated securely.
     */
    template <typename T>
    using SecureVector = std::vector<T, SecureAllocator<T>>;

    /**
     * RawVector is a standard vector type that does not use SecureAllocator. It is used for non-sensitive data where
     * secure memory allocation is not required.
     */
    template <typename T>
    using RawVector = std::vector<T>;

    /**
     * SecureBytes is a type alias for SecureVector of uint8_t, which is used to represent secure byte arrays. This is
     * useful for cryptographic operations where sensitive data needs to be stored securely in memory.
     */
    using SecureBytes = SecureVector<std::uint8_t>;

    /**
     * RawBytes is a type alias for RawVector of uint8_t, which is used to represent byte arrays that do not require
     * secure memory allocation. This is useful for non-sensitive data where performance is more critical than security.
     */
    using RawBytes = RawVector<std::uint8_t>;

    /**
     * ViewBytes is a type alias for std::span of const uint8_t, which provides a non-owning view over a contiguous
     * sequence of bytes. This is useful for passing around byte data without copying it, allowing for efficient size
     * and data access.
     */
    using ViewBytes = std::span<const std::uint8_t>;


    /**
     * This operator== is a no-op for SecureAllocator, meaning that it always returns true. This is because SecureAllocator
     * is designed to be a stateless allocator, and the equality of two instances does not depend on their internal state.
     * @return Always true.
     */
    template <typename T, typename U>
    auto operator==(
        const SecureAllocator<T> &,
        const SecureAllocator<U> &) noexcept
        -> bool {
        return true;
    }


    /**
     * This operator!= is a no-op for SecureAllocator, meaning that it always returns false. This is because SecureAllocator
     * is designed to be a stateless allocator, and the inequality of two instances does not depend on their internal state.
     * @return Always false.
     */
    template <typename T, typename U>
    auto operator!=(
        const SecureAllocator<T> &,
        const SecureAllocator<U> &) noexcept
        -> bool {
        return false;
    }
}

/**
 * The SecureAllocator is a custom allocator for SecureVector that uses OpenSSL's secure memory functions. This provides
 * a standard way to allocate and deallocate memory securely, ensuring that sensitive data is not left in memory after
 * use.
 * @tparam T The type of elements to be allocated.
 */
template <typename T>
struct snet::crypt::bytes::SecureAllocator {
    using value_type = T;
    using is_always_equal = std::true_type;

    SecureAllocator() noexcept = default;

    ~SecureAllocator() = default;

    /**
     * The allocation function uses OpenSSL's secure_malloc to allocate memory for T objects. This places the allocated
     * bytes in a secure memory area, which is not swappable to disk, thus protecting sensitive data from being exposed
     * in case of a memory dump or similar attack.
     * @param n The number of elements to allocate.
     * @return A pointer to the allocated memory for T objects.
     */
    static auto allocate(const std::size_t n) -> T* {
        return static_cast<T*>(openssl::OPENSSL_secure_malloc(n * sizeof(T)));
    }

    /**
     * The deallocation function uses OpenSSL's secure_free to deallocate memory for T objects. This ensures that the
     * memory is securely freed, preventing any sensitive data from lingering in memory after use.
     * @param ptr The pointer to the memory to deallocate.
     * @param n The number of elements that were allocated.
     */
    static auto deallocate(T *ptr, const std::size_t n) -> void {
        openssl::OPENSSL_cleanse(ptr, sizeof(T) * n);
        openssl::OPENSSL_secure_free(ptr);
    }

    /**
     * The construct function uses placement new to construct an object of type U at the given pointer with the
     * provided arguments. This allows for in-place construction of objects in the allocated secure memory.
     * @tparam U The type of the object to construct.
     * @tparam Args The types of the arguments to pass to the constructor of U.
     * @param ptr The pointer to the memory where the object should be constructed.
     * @param args The arguments to pass to the constructor of U.
     */
    template <typename U, typename... Args>
    static auto construct(U *ptr, Args &&... args) -> void {
        ::new(static_cast<void*>(ptr)) U(std::forward<Args>(args)...);
    }

    /**
     * The destroy function calls the destructor of the object pointed to by ptr. This is necessary to properly
     * clean up the object before deallocating its memory. It ensures that any resources held by the object are
     * released.
     * @tparam U The type of the object to destroy.
     * @param ptr The pointer to the object to destroy.
     */
    template <typename U>
    static auto destroy(U *ptr) noexcept -> void {
        ptr->~U();
    }

    [[nodiscard]]
    auto max_size() const noexcept -> std::size_t {
        return std::numeric_limits<std::size_t>::max() / sizeof(T);
    }
};


/**
 * This operator+ concatenates two RawBytes objects and returns a new RawBytes object containing the combined data. It
 * uses the @c append_range method to efficiently append the contents of the second RawBytes to the first.
 * @param a The first @c RawBytes object.
 * @param b The second @c RawBytes object.
 * @return A new @c RawBytes object containing the concatenated data from @c a and @c b.
 */
export inline auto operator+(
    const snet::crypt::bytes::RawBytes &a,
    const snet::crypt::bytes::RawBytes &b)
    -> snet::crypt::bytes::RawBytes {
    auto result = a;
    result.reserve(a.size() + b.size());
    result.append_range(b);
    return result;
}


export inline auto operator+=(
    snet::crypt::bytes::RawBytes &a,
    const snet::crypt::bytes::RawBytes &b)
    -> snet::crypt::bytes::RawBytes& {
    a.reserve(a.size() + b.size());
    a.append_range(b);
    return a;
}


export namespace snet::crypt::bytes {
    auto immediate_release(SecureBytes &data) -> void {
        SecureBytes().swap(data);
    }
}

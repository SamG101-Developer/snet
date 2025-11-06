export module snet.net.fragmentation;
import std;


export namespace snet::net {
    /**
     * The @c FragmentationHeader allows for TCP messages to be sent over a UDP socket by fragmenting them into smaller
     * sizes with some metadata. The header is prepended to each fragment. Some data is consistent across all fragments,
     * such as the id, length and checksum.
     */
    struct FragHeader {
        std::uint32_t msg_id;
        std::uint16_t frag_offset;
        std::uint16_t frag_count;
        std::uint16_t frag_length;
        std::uint64_t total_length;
        std::uint32_t total_checksum;
    };

    /**
     * The @c Fragment structure stores a fragment's header and data. These are paired so that the offset and length of
     * each fragment can be used to form the final buffer with string injection for this fragment.
     */
    struct Fragment {
        FragHeader header;
        std::vector<std::uint8_t> data;
    };

    /**
     * A @c Message is a collection of fragments that have been received for a specific message ID. It also stores the
     * time the first fragment was received to allow for timeout handling, interacted with by a cleanup thread. Store
     * associated connection information for message handlers.
     */
    struct Message {
        std::vector<Fragment> fragments;
        std::chrono::steady_clock::time_point first_received;
    };
}

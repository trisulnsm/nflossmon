#pragma once
#include <cstdint>
#include <unordered_map>
#include <arpa/inet.h>
struct IPFIXSetHeader {
    uint16_t set_id;
    uint16_t length;
};

struct IPFIXTemplateHeader {
    uint16_t template_id;
    uint16_t field_count;
};

class CIPFIXTracker {
public:
    // Add a template mapping
    void add_template(uint16_t template_id, uint16_t total_length) {
        template_lengths[template_id] = total_length;
    }

    // Calculate total flows in an IPFIX record
    uint32_t calculate_flows(const uint8_t* ipfix_data, uint16_t total_length) {
        uint32_t total_flows = 0;
        uint16_t offset = 0;

        while (offset < total_length) {
            const IPFIXSetHeader* set_header = reinterpret_cast<const IPFIXSetHeader*>(ipfix_data + offset);
            uint16_t set_id = ntohs(set_header->set_id);
            uint16_t set_length = ntohs(set_header->length);

            if (set_id == 2) {
                // Template Set - process and store template information
                process_template_set(ipfix_data + offset + sizeof(IPFIXSetHeader), 
                                  set_length - sizeof(IPFIXSetHeader));
            }
            else if (set_id >= 256) {
                // Data Set - calculate flows based on template
                if (template_lengths.find(set_id) != template_lengths.end()) {
                    uint16_t record_length = template_lengths[set_id];
                    if (record_length > 0) {
                        uint32_t num_records = (set_length - sizeof(IPFIXSetHeader)) / record_length;
                        total_flows += num_records;
                    }
                }
            }

            offset += set_length;
        }

        return total_flows;
    }

private:
    void process_template_set(const uint8_t* template_data, uint16_t template_length) {
        uint16_t offset = 0;
        while (offset < template_length) {
            const IPFIXTemplateHeader* tmpl_header = 
                reinterpret_cast<const IPFIXTemplateHeader*>(template_data + offset);
            
            uint16_t template_id = ntohs(tmpl_header->template_id);
            uint16_t field_count = ntohs(tmpl_header->field_count);
            
            // Calculate total length of all fields
            uint16_t total_length = 0;
            const uint8_t* field_ptr = template_data + offset + sizeof(IPFIXTemplateHeader);
            
            for (uint16_t i = 0; i < field_count; i++) {
                uint16_t field_type = ntohs(*reinterpret_cast<const uint16_t*>(field_ptr));
                total_length += ntohs(*reinterpret_cast<const uint16_t*>(field_ptr + 2));
                if (field_type & 0x8000) {
                    field_ptr += 4;
                    offset += 4;
                }
                field_ptr += 4;
                offset += 4;
            }
            
            add_template(template_id, total_length);
            offset += sizeof(IPFIXTemplateHeader);
        }
    }

    std::unordered_map<uint16_t, uint16_t> template_lengths; // template_id -> total_length
}; 
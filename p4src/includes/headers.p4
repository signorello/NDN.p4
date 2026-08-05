/*<This file is part of NDN.p4,i.e., an NDN implementation written in P4.>
Copyright (C) 2016, the University of Luxembourg
Salvatore Signorello <salvatore.signorello@uni.lu>

NDN.p4 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

NDN.p4 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with NDN.p4.  If not, see <http://www.gnu.org/licenses/>.
*/

// The following header definition follows the packet specification 0.2-alpha-3 that can be read at
// https://named-data.net/

#define NAME_HASH_SIZE 32;


//*************************************//
//              METADATA	       //
//*************************************//

header_type name_metadata_t {
    fields{
	name_hash : 16;
	name_size : 8;
	name_mask : 16;
	comp_len  : 8;
	components  : 8;
    }
}

header_type components_metadata_t {
    fields {
	c1 : 16;
	c2 : 16;
	c3 : 16;
	c4 : 16;
    }
}

header_type ingress_metadata_t {
  fields {
    tmp : 8;
  }
}

header_type flow_metadata_t {
  fields {
    isInPIT : 8;
    hasFIBentry : 8;
    packetType : 8;
  }
}

metadata name_metadata_t name_metadata;
metadata flow_metadata_t flow_metadata;
metadata ingress_metadata_t pit_metadata;
metadata components_metadata_t comp_metadata;

/*************************************/
//              HEADERS              //
/*************************************/

header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}

// The following two header definitions are meant to extract
// two possible NDNLP headers into fixed-size blocks
header_type block_112b_t {
    fields {
	total : 112;
    }
}

header_type block_144b_t {
    fields {
	total : 144;
    }
}

// this fixedTLV_t header is meant to extract TLV fields
// whose length encoding is 1B and which contains actual values (and not nested TLVs).
// This header is used to extract name components, for instance.
header_type fixedTLV_t {
  fields{
      tlv_code : 8;
      tlv_length : 8;
      tlv_value : *;
  }
  length : tlv_length + 2;
  max_length : 255;
}

// the four following headers are meant to represent the
// variable-size encoding format of the TLV Length field
header_type smallTL_t {
  fields{
    tl_code : 8;
    tl_length : 8;
  }
}
header_type mediumTL_t {
  fields{
    tl_code : 8;
    tl_len_code : 8;
    tl_length : 16;
  }
}
header_type bigTL_t {
  fields{
    tl_code : 8;
    tl_len_code : 8;
    tl_length : 32;
  }
}
header_type hugeTL_t {
  fields{
    tl_code : 8;
    tl_len_code : 8;
    tl_length : 64;
  }
}

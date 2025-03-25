package ids_types;
  parameter N_PIPES = 2;
  parameter PDU_SIZE = 8*512; // In bits
  parameter PACKET_SIZE = 8*1500; // In bits
  parameter GID_WIDTH = 16;
  parameter PID_WIDTH = 16;
  parameter TOTAL_GROUPS = 512;
  parameter MAX_GROUPS = 32;

  typedef logic [GID_WIDTH-1:0] group_id_t;
  typedef logic [$clog2(TOTAL_GROUPS)-1:0] match_req_vector_t;
  typedef logic [PACKET_SIZE-1:0] packet_data_t;
  typedef logic [PDU_SIZE-1:0] pdu_data_t;

  typedef struct packed
  {
    logic valid;
    group_id_t [MAX_GROUPS-1:0] groups;
    logic [$clog2(MAX_GROUPS)-1:0] num_groups;
    packet_data_t data;
  } buffer_entry_t;

  

endpackage
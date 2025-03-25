//`include "./struct_s.sv"

package full_matcher_types;
  parameter N_CB_CHN = 2;
  parameter SYMBOL_WIDTH = 8;
  parameter NFA_STATUS_W = 3;
  parameter NO_RULE = '0;
  parameter NULL_SYMBOL = '0;
  parameter N_FIFO_ENTRY = 1;
  parameter MAX_PACKET_SIZE = 8*512; // In bits
  parameter RID_WIDTH = 16; // For some reason I can't get this from struct_s
  parameter PID_WIDTH = 16;
  parameter N_PIPES = 2;
  parameter PDU_SIZE = 8*512; // In bits
  parameter PACKET_SIZE = 8*1500; // In bits
  parameter GID_WIDTH = 16;
  parameter TOTAL_GROUPS = 512;
  parameter MAX_GROUPS = 32;

  typedef logic [RID_WIDTH-1:0] rule_id_t;
  typedef logic [SYMBOL_WIDTH-1:0] symbol_t;
  typedef logic [PID_WIDTH-1:0] data_id_t;
  typedef logic [GID_WIDTH-1:0] group_id_t;
  typedef logic [$clog2(TOTAL_GROUPS)-1:0] match_req_vector_t;
  typedef logic [PACKET_SIZE-1:0] packet_data_t;
  typedef logic [PDU_SIZE-1:0] pdu_data_t;

  typedef enum logic [NFA_STATUS_W-1:0] {
    IDLE,
    PROC,
    FWD,
    DROP,
    ERR
  } nfa_status_t;

  typedef struct packed
  {
    logic valid;
    rule_id_t [MAX_GROUPS-1:0] groups;
    logic [$clog2(MAX_GROUPS)-1:0] num_groups, group_pointer;
    data_id_t data_id;
    logic [MAX_PACKET_SIZE-1:0] data;
  } queue_entry_t;

  typedef struct packed {
    logic [MAX_PACKET_SIZE-1:0] data;
    rule_id_t rule_id;
    data_id_t data_id;
    logic valid;
  } stg1_msg_t;

  typedef struct packed {
    logic valid;
    rule_id_t [MAX_GROUPS-1:0] groups;
    logic [7:0] num_groups, group_pointer;
    data_id_t data_id;
    logic [MAX_PACKET_SIZE-1:0] data;
  } stg2_msg_t;

  typedef struct packed
  {
    logic valid;
    group_id_t [MAX_GROUPS-1:0] groups;
    logic [$clog2(MAX_GROUPS)-1:0] num_groups;
    packet_data_t data;
  } buffer_entry_t;

endpackage
//`include "../struct_s.sv"

interface n_wide_fifo_if #(
  parameter N_FIFO_ENTRY_LOCAL = 8
);

  import full_matcher_types::*;

  logic [$clog2(N_FIFO_ENTRY_LOCAL):0] raddr;
  logic inv_entry;
  logic done; // done matching current group
  logic last; // last group when writing
  logic wen;
  logic [MAX_PACKET_SIZE-1:0] wdata; // change later
  rule_id_t rule_id;
  data_id_t data_id;
  
  //queue_entry_t out_entry; // doesn't work with multiple interfaces for some reason
  logic valid_out;
  logic [$clog2(MAX_GROUPS)-1:0] cur_groups;
  rule_id_t rule_id_out;
  data_id_t data_id_out;
  logic [MAX_PACKET_SIZE-1:0] data_out;
  logic [$clog2(N_FIFO_ENTRY_LOCAL):0] head;
  logic [$clog2(N_FIFO_ENTRY_LOCAL):0] tail;
  logic [$clog2(N_FIFO_ENTRY_LOCAL):0] capacity;

  // modport fifo (
  //   input raddr, inv_entry, wen, wdata, rule_id,
  //   output out_entry, head, tail, capacity
  // );

  // modport queue (
  //   input out_entry, head, tail, capacity,
  //   output raddr, inv_entry, wen, wdata, rule_id
  // );

  modport fifo (
    input raddr, inv_entry, done, last, wen, wdata, rule_id, data_id,
    output valid_out, cur_groups, rule_id_out, data_id_out, data_out, head, tail, capacity
  );

  modport queue (
    input valid_out, cur_groups, rule_id_out, data_id_out, data_out, head, tail, capacity,
    output raddr, inv_entry, done, rule_id, data_id
  );

  modport balancer (
    input capacity,
    output wen, last, wdata, rule_id, data_id
  );
endinterface
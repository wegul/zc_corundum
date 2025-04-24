////include "./crossbar_if.sv"
//`include "./full_matcher_if.sv"
//`include "./n_wide_fifo_if.sv"

import full_matcher_types::*;

module packet_queue_load_balancer
(
  input logic clk, n_rst,
  full_matcher_if.fm fif,
  n_wide_fifo_if.balancer fifoif [N_CB_CHN-1:0]
);

  genvar i;

  logic full, full_latch;

  logic [$clog2(N_CB_CHN):0] highest_channel, cur_channel, highest_channel_next, cur_channel_next;
  logic [N_CB_CHN-1:0] [$clog2(fifoif[0].N_FIFO_ENTRY_LOCAL):0] capacity_array;  // compiler made me do this

  typedef enum {IDLE, WRITING} write_state_t;

  write_state_t write_state, write_state_next;
  logic [$clog2(N_CB_CHN):0] write_channel, write_channel_next;

  data_id_t data_id_gen;

  always_ff @ (posedge clk, negedge n_rst)
  begin
    if (~n_rst)
    begin
      highest_channel <= '0;
      cur_channel <= '0;
      write_state <= IDLE;
      write_channel <= '0;
      data_id_gen <= '0;
    end
    else
    begin
      highest_channel <= highest_channel_next;
      cur_channel <= cur_channel_next;
      write_state <= write_state_next;
      write_channel <= write_channel_next;
      if (fif.last)
        data_id_gen <= data_id_gen + 'd1;
    end
  end

  always_comb
  begin: WRITE_STATE_LOGIC
    write_state_next = write_state;
    write_channel_next = highest_channel;

    if (~full && fif.valid && ~fif.last)
    begin
      write_state_next = WRITING;
    end
    if (write_state == WRITING)
    begin
      write_channel_next = write_channel;
      if (fif.last)
        write_state_next = IDLE;
    end
  end

  always_comb
  begin: LEAST_CAPACITY_LOGIC
    highest_channel_next = highest_channel;
    cur_channel_next = cur_channel + 'd1;
    if (cur_channel == N_CB_CHN - 1)
      cur_channel_next = '0;
    if (capacity_array[cur_channel] > capacity_array[highest_channel])
      highest_channel_next = cur_channel;
  end

  generate
  for (i = 0; i < N_CB_CHN; i++)
  begin
    always_comb
    begin: WRITE_LOGIC
      //for (int i = 0; i < N_CB_CHN; i++)
      //begin
        fifoif[i].wen = '0;
        fifoif[i].last = 1'b0;
        fifoif[i].wdata = '0;
        fifoif[i].rule_id = NO_RULE;
        fifoif[i].data_id = '0;
        if (i == write_channel) // NOTE: need a write state for streaming so we don't move around during a write
        begin
          if (~full)
          begin
            fifoif[i].wen = fif.valid;
            fifoif[i].last = fif.last & fif.valid;
            fifoif[i].wdata = fif.data;
            fifoif[i].rule_id = fif.rule_id;
            fifoif[i].data_id = data_id_gen;
          end
        end
      //end
    end

    assign capacity_array[i] = fifoif[i].capacity;
  end
  endgenerate

  assign full = ~(|capacity_array[write_channel]);

  always_ff @ (posedge clk, negedge n_rst)
  begin: FULL_LATCH
    if (~n_rst)
      full_latch <= 1'b0;
    else
    begin
      if (fif.valid && ~fif.last && full)
        full_latch <= 1'b1;
      else
        full_latch <= 1'b0;
    end
  end

  // always_comb
  // begin: OVERFLOW_RESPONSE_LOGIC
  //   fif.data_resp = '0;
  //   fif.rule_id_resp = '0;
  //   fif.last_resp = '0;
  //   fif.valid_resp = '0;
  //   if (full | full_latch)
  //   begin
  //     fif.data_resp = fif.data;
  //     fif.rule_id_resp = fif.rule_id;
  //     fif.last_resp = fif.last;
  //     fif.valid_resp = fif.valid;
  //   end
  // end

endmodule
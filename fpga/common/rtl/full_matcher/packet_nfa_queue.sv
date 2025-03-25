//include "./crossbar_if.sv"
`include "./full_matcher_if.sv"
`include "./n_wide_fifo_if.sv"

module packet_nfa_queue
(
  input logic clk, n_rst,
  full_matcher_if.fm fif,
  crossbar_if.arb cif
);

  import full_matcher_types::*;

  typedef enum logic [2:0] {SEARCH, CHECK, PROC, DONE, CLEAR} channel_state_t;

  n_wide_fifo_if fifoif();

  channel_state_t [N_CB_CHN-1:0] channel_state, channel_state_next;
  logic [N_CB_CHN-1:0] [$clog2(fifoif.N_FIFO_ENTRY_LOCAL):0] channel_pointer, channel_pointer_next;
  logic [N_CB_CHN-1:0] [$clog2(MAX_PACKET_SIZE):0] byte_count, byte_count_next;

  n_wide_fifo fifo (.clk, .n_rst,
                    .fif(fifoif));

  always_ff @ (posedge clk, negedge n_rst)
  begin
    if (~n_rst)
    begin
      for (int i = 0; i < N_CB_CHN; i++)
      begin
        channel_state[i] <= SEARCH;
        channel_pointer[i] <= '0;
        byte_count[i] <= '0;
      end
    end
    else
    begin
      for (int i = 0; i < N_CB_CHN; i++)
      begin
        channel_state[i] <= channel_state_next[i];
        channel_pointer[i] <= channel_pointer_next[i];
        byte_count[i] <= byte_count_next[i];
      end
    end
  end

  always_comb
  begin: CHANNEL_POINTER_LOGIC
    for (int i = 0; i < N_CB_CHN; i++)
    begin
      channel_pointer_next[i] = channel_pointer[i];
      if (channel_state[i] == SEARCH && channel_state_next[i] != CHECK)
        if (channel_pointer[i] == fifoif.N_FIFO_ENTRY_LOCAL-1)
          channel_pointer_next[i] = '0;
        else if (channel_pointer[i] == fifoif.tail)
          channel_pointer_next[i] = fifoif.head;
        else
          channel_pointer_next[i] = channel_pointer[i] + 'd1;
      if (channel_state[i] == CLEAR)
        channel_pointer_next[i] = channel_pointer[i] == fifoif.head ? channel_pointer[i] + 'd1 : fifoif.head;
    end
  end

  always_comb
  begin: BYTE_COUNT_LOGIC
    for (int i = 0; i < N_CB_CHN; i++)
    begin
      byte_count_next[i] = '0;
      if (channel_state[i] == PROC)
        byte_count_next[i] = byte_count[i] + 'd1;
    end
  end

  always_comb
  begin: NEXT_STATE_LOGIC
    for (int i = 0; i < N_CB_CHN; i++)
    begin
      channel_state_next[i] = channel_state[i];

      case (channel_state[i])
        SEARCH : begin
          channel_state_next[i] = CHECK;
          for (int j = 0; j < N_CB_CHN; j++)
            if (channel_pointer[i] == channel_pointer[j] && (j < i || channel_state[j] != SEARCH))
              channel_state_next[i] = SEARCH;
          if (~fifoif.out_entry[i].valid)
            channel_state_next[i] = SEARCH;
        end
        CHECK  : begin
          channel_state_next[i] = SEARCH;
          if (~cif.busy[i] && fifoif.out_entry[i].valid) // May not need 2nd clause anymore
            channel_state_next[i] = PROC;
        end
        PROC   : begin
          if (fifoif.out_entry[i].data[8*byte_count[i]+:8] == 8'h00)
            channel_state_next[i] = DONE;
          if (byte_count[i] == 'd63)
            channel_state_next[i] = DONE;
        end
        DONE   : begin
          channel_state_next[i] = CLEAR;
        end
        CLEAR  : begin
          channel_state_next[i] = SEARCH;
        end
      endcase
    end
  end

  always_comb
  begin: OUTPUT_LOGIC
    for (int i = 0; i < N_CB_CHN; i++)
    begin
      cif.rule_req[i] = 1'b0;
      cif.done[i] = 1'b0;
      cif.rule_id[i] = NO_RULE;
      cif.in_symbol[i] = NULL_SYMBOL;
      fifoif.inv_entry[i] = 1'b0;
      case (channel_state[i])
        SEARCH : begin
          cif.rule_req[i] = 1'b0;
          cif.done[i] = 1'b0;
          cif.rule_id[i] = NO_RULE;
          cif.in_symbol[i] = NULL_SYMBOL;
          fifoif.inv_entry[i] = 1'b0;
        end
        CHECK  : begin
          cif.rule_req[i] = 1'b1;
          cif.done[i] = 1'b0;
          cif.rule_id[i] = fifoif.out_entry[i].rule_id;
          cif.in_symbol[i] = fifoif.out_entry[i].data[7:0];
          fifoif.inv_entry[i] = 1'b0;
        end
        PROC   : begin
          cif.rule_req[i] = 1'b1;
          cif.done[i] = 1'b0;
          cif.rule_id[i] = fifoif.out_entry[i].rule_id;
          cif.in_symbol[i] = fifoif.out_entry[i].data[8*byte_count[i]+:8];
          fifoif.inv_entry[i] = 1'b0;
        end
        DONE   : begin // Might need an extra state before DONE due to pipelining...
          cif.rule_req[i] = 1'b1;
          cif.done[i] = 1'b1;
          cif.rule_id[i] = fifoif.out_entry[i].rule_id;
          cif.in_symbol[i] = fifoif.out_entry[i].data[8*byte_count[i]+:8];
          fifoif.inv_entry[i] = 1'b0;
        end
        CLEAR  : begin
          cif.rule_req[i] = 1'b0; // 0 or 1?
          cif.done[i] = 1'b0;
          cif.rule_id[i] = fifoif.out_entry[i].rule_id;
          cif.in_symbol[i] = NULL_SYMBOL;
          fifoif.inv_entry[i] = 1'b1;
        end
      endcase
    end
  end

  always_comb
  begin: INTERFACE_ASSIGNMENTS
    fifoif.wen = fif.valid;
    fifoif.wdata = fif.data;
    fifoif.rule_id = fif.rule_id;
    for (int i = 0; i < N_CB_CHN; i++)
    begin
      fifoif.raddr[i] = channel_pointer[i];
    end
  end

endmodule
////include "./crossbar_if.sv"
//`include "./full_matcher_if.sv"
//`include "./n_wide_fifo_if.sv"

module multi_packet_nfa_queue
(
  input logic clk, n_rst,
  full_matcher_if.fm fif,
  nfa_if.arb nif
);

  import full_matcher_types::*;

  genvar i;

  typedef enum logic [2:0] {SEARCH, CHECK, PROC, WAIT_LATCH1, WAIT_LATCH2, DONE, CLEAR} channel_state_t;

  parameter N_FIFO_ENTRY_LOCAL = N_FIFO_ENTRY;
  parameter BRAM_WAIT_COUNT = 8;
  

  n_wide_fifo_if #(.N_FIFO_ENTRY_LOCAL(N_FIFO_ENTRY)) fifoif [N_CB_CHN-1:0] ();

  channel_state_t [N_CB_CHN-1:0] channel_state; // status of the channel
  channel_state_t [N_CB_CHN-1:0] channel_state_next;
  logic [N_CB_CHN-1:0] [$clog2(N_FIFO_ENTRY_LOCAL):0] channel_pointer, channel_pointer_next; // which entry in the queue the channel is accessing
  logic [N_CB_CHN-1:0] [$clog2(MAX_PACKET_SIZE/8):0] byte_count, byte_count_next; // which byte is it processing
  logic [N_CB_CHN-1:0] [3:0] bram_wait, bram_wait_next; // counter to wait for bram pipeline to fill
  stg2_msg_t [N_CB_CHN-1:0] response; // message for stage 1

  packet_queue_load_balancer load_balancer (.clk, .n_rst, .fif, .fifoif);

  //response_unit ru (.clk, .n_rst, .fif, .response);

  n_wide_fifo fifo [N_CB_CHN-1:0] (.clk, .n_rst,
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
        bram_wait[i] <= BRAM_WAIT_COUNT;
      end
    end
    else
    begin
      for (int i = 0; i < N_CB_CHN; i++)
      begin
        channel_state[i] <= channel_state_next[i];
        channel_pointer[i] <= channel_pointer_next[i];
        byte_count[i] <= byte_count_next[i];
        bram_wait[i] <= bram_wait_next[i];
      end
    end
  end

  generate // Needed - fifoif does not like for loops in always comb
  for (i = 0; i < N_CB_CHN; i++)
  begin
    always_comb
    begin: CHANNEL_POINTER_LOGIC
      //for (int i = 0; i < N_CB_CHN; i++)
      //begin
        channel_pointer_next[i] = channel_pointer[i];
        if (channel_state[i] == SEARCH && channel_state_next[i] != CHECK || channel_state[i] == CHECK && channel_state_next[i] == SEARCH)
          if (channel_pointer[i] == N_FIFO_ENTRY_LOCAL-1)
            channel_pointer_next[i] = '0;
          // else if (channel_pointer[i] == fifoif[i].tail)
          //   channel_pointer_next[i] = fifoif[i].head;
          else
            channel_pointer_next[i] = channel_pointer[i] + 'd1;
        if (channel_state[i] == CLEAR)
          // channel_pointer_next[i] = channel_pointer[i] == fifoif[i].head ? channel_pointer[i] + 'd1 : fifoif[i].head;
          channel_pointer_next[i] = channel_pointer[i] == N_FIFO_ENTRY_LOCAL-1 ? '0 : channel_pointer[i] + 'd1;
      //end
    end

    always_comb
    begin: BYTE_COUNT_LOGIC
      //for (int i = 0; i < N_CB_CHN; i++)
      //begin
        byte_count_next[i] = '0;
        if (channel_state[i] == PROC)
          byte_count_next[i] = byte_count[i] + 'd1;
      //end
    end

    always_comb
    begin: BRAM_WAIT_LOGIC
      bram_wait_next[i] = BRAM_WAIT_COUNT;
      if (channel_state[i] == CHECK)
        bram_wait_next[i] = bram_wait[i] - 'd1;
    end

    always_comb
    begin: NEXT_STATE_LOGIC
      //for (int i = 0; i < N_CB_CHN; i++)
      //begin
        channel_state_next[i] = channel_state[i];

        case (channel_state[i])
          SEARCH : begin
            channel_state_next[i] = CHECK;
            //for (int j = 0; j < N_CB_CHN; j++)
            //  if (channel_pointer[i] == channel_pointer[j] && (j < i || channel_state[j] != SEARCH))
            //    channel_state_next[i] = SEARCH;
            if (~fifoif[i].valid_out) // this is triggering when it shouldn't be, seems to only not trigger for fifoif[1]
              channel_state_next[i] = SEARCH;
          end
          CHECK  : begin
            channel_state_next[i] = SEARCH;
            if (bram_wait[i] != 'd0)
              channel_state_next[i] = CHECK;
            else if (nif.ready[i] && fifoif[i].valid_out) // May not need 2nd clause anymore
              channel_state_next[i] = PROC;
          end
          PROC   : begin
            if (byte_count[i] == MAX_PACKET_SIZE/8) // why was this 'd63?
              channel_state_next[i] = WAIT_LATCH1;
          end
          WAIT_LATCH1 : begin
            channel_state_next[i] = WAIT_LATCH2;
          end
          WAIT_LATCH2 : begin
            channel_state_next[i] = DONE;
          end
          DONE   : begin
            if (fifoif[i].cur_groups == 'd1 || nif.match[i])
              channel_state_next[i] = CLEAR;
            else
              channel_state_next[i] = SEARCH;
          end
          CLEAR  : begin
            channel_state_next[i] = SEARCH;
          end
        endcase
      //end
    end

    always_comb
    begin: OUTPUT_LOGIC
      //for (int i = 0; i < N_CB_CHN; i++)
      //begin
        nif.request[i] = 1'b0;
        nif.clear[i] = 1'b0;
        nif.id[i] = NO_RULE;
        nif.symbol[i] = NULL_SYMBOL;
        fifoif[i].inv_entry = 1'b0;
        fifoif[i].done = 1'b0;
        response[i] = '0;
        case (channel_state[i])
          SEARCH : begin
            nif.request[i] = 1'b0;
            nif.clear[i] = 1'b0;
            nif.id[i] = NO_RULE;
            nif.symbol[i] = NULL_SYMBOL;
            fifoif[i].inv_entry = 1'b0;
            fifoif[i].done = 1'b0;
          end
          CHECK  : begin
            nif.request[i] = 1'b1;
            nif.clear[i] = 1'b0;
            nif.id[i] = fifoif[i].rule_id_out;
            nif.symbol[i] = fifoif[i].data_out[7:0];
            fifoif[i].inv_entry = 1'b0;
            fifoif[i].done = 1'b0;
          end
          PROC   : begin
            nif.request[i] = 1'b1;
            nif.clear[i] = 1'b0;
            nif.id[i] = fifoif[i].rule_id_out;
            nif.symbol[i] = fifoif[i].data_out[8*byte_count[i]+:8];
            fifoif[i].inv_entry = 1'b0;
            fifoif[i].done = 1'b0;
          end
          WAIT_LATCH1: begin
            nif.request[i] = 1'b1; // 1 or 0? 0 means we can pipeline
            nif.clear[i] = 1'b0; // same with this, 1 or 0?
            nif.id[i] = fifoif[i].rule_id_out;
            nif.symbol[i] = fifoif[i].data_out[8*byte_count[i]+:8];
            fifoif[i].inv_entry = 1'b0;
            fifoif[i].done = 1'b0;
          end
          WAIT_LATCH2: begin
            nif.request[i] = 1'b1; // 1 or 0? 0 means we can pipeline
            nif.clear[i] = 1'b0; // same with this, 1 or 0?
            nif.id[i] = fifoif[i].rule_id_out;
            nif.symbol[i] = fifoif[i].data_out[8*byte_count[i]+:8];
            fifoif[i].inv_entry = 1'b0;
            fifoif[i].done = 1'b0;
          end
          DONE   : begin
            nif.request[i] = 1'b1;
            nif.clear[i] = 1'b1;
            nif.id[i] = fifoif[i].rule_id_out;
            nif.symbol[i] = fifoif[i].data_out[8*byte_count[i]+:8];
            fifoif[i].inv_entry = 1'b0;
            fifoif[i].done = 1'b1;
            // if (nif.match[i] || fifoif[i].cur_groups == 'd1)
            // begin
            //   response[i].rule_id_resp = fifoif[i].rule_id_out;
            //   response[i].data_id_resp = fifoif[i].data_id_out;
            //   response[i].match = nif.match[i];
            //   response[i].valid = 1'b1;
            // end
          end
          CLEAR  : begin
            nif.request[i] = 1'b0; // 0 or 1?
            nif.clear[i] = 1'b0;
            nif.id[i] = fifoif[i].rule_id_out;
            nif.symbol[i] = NULL_SYMBOL;
            fifoif[i].inv_entry = 1'b1;
            fifoif[i].done = 1'b0;
          end
        endcase
      //end
    end

     always_comb
     begin: INTERFACE_ASSIGNMENTS
       //fifoif[i].wen = fif.valid;
       //fifoif[i].wdata = fif.data;
       //fifoif[i].rule_id = fif.rule_id;
       //for (int i = 0; i < N_CB_CHN; i++)
       //begin
         fifoif[i].raddr = channel_pointer[i];
       //end
     end

     
  end
  endgenerate

  //assign fif.match = |nif.match;

  // always_ff @ (negedge clk)
  //    begin // TODO: try moving this outside of the generate
  //       //for (int j = 0; j < 2; j++)
  //       //begin
  //       // no matter what this always prints fifoif[1].out_entry and it won't let me print 0
  //       $display("At %t ps fifoif[%d].rule_id_out[0] = %d\n", $time, 1, fifo[0].fif.rule_id_out[0]);
  //       //end
  //    end
  //assign fifoif.raddr[0] = channel_pointer; // this works?

  // seems to only care about fifoif[1]
  //  out_entry only seems to be tied together, generate statement can't differentiate and always chooses fifoif[1]
  //  upon simulation, Vivado seems to act like fifoif[0].out_entry[0] is the same object as fifoif[1].out_entry[0]

endmodule
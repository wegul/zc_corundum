`timescale 1 ns/10 ps  // time-unit = 1 ns, precision = 10 ps
//`include "./src/struct_s.sv"
//`include "./src/full_matcher_types.sv"
`include "./full_matcher_if.sv"
//include "./crossbar_if.sv"

module packet_nfa_queue_tb;

  import full_matcher_types::*;

  // constants
  localparam PERIOD = 10;
  localparam NUM_NFA = 1024;

  // clk, n_rst
  logic clk, n_rst;
  initial clk = 1'b0;
  // interfaces
  full_matcher_if fif();
  nfa_if nif();

  // tb signals
  int test_num = 0;
  string test_name = "INIT";
  typedef struct {
    int cur_idx;
    string pattern;
  } nfa_t; // TODO: add replication for assoc test
  nfa_t nfa [NUM_NFA-1:0];
  logic [MAX_PACKET_SIZE-1:0] input_data;

  // DUT
  `define USE_MULTI_QUEUE
  `ifdef USE_MULTI_QUEUE
  multi_packet_nfa_queue DUT0(
    clk,
    n_rst,
    fif,
    nif
  );
  `else
  packet_nfa_queue DUT0(
    clk,
    n_rst,
    fif,
    cif
  );
  `endif

  // Tasks
  task automatic send_packet;
    input rule_id_t rule_id;
    input logic [MAX_PACKET_SIZE-1:0] data;
  begin
    fif.valid = 1'b1;
    fif.rule_id = rule_id;
    fif.data = data;
    @(negedge clk);
    fif.valid = 1'b0;
  end
  endtask

  // always blocks
  always #(PERIOD/2) clk++;

  // always @ (negedge clk)
  // begin
  //   for (int i = 0; i < N_CB_CHN; i++)
  //     for (int j = 0; j < N_CB_CHN; j++)
  //       if (i != j && cif.index[i] != NO_RULE && cif.index[j] != NO_RULE)
  //         assert (cif.index[i] != cif.index[j]) 
  //         else   $display("ERROR @ %g: channel %d's index matches channel %d's index", $time, i, j);
  // end

  // always @ (negedge clk) // state checking
  // begin
  //   for (int i = 0; i < N_CB_CHN; i++)
  //     case (cif.nfa_status[i])
  //       FWD: begin
  //         assert (~cif.n_clear[i] && cif.index[i] != NO_RULE) 
  //         else   $display("ERROR @ %g: channel %d not clearing the correct rule", $time, i);
  //       end
  //       DROP: begin
  //         assert (~cif.n_clear[i] && cif.index[i] != NO_RULE) 
  //         else   $display("ERROR @ %g: channel %d not clearing the correct rule", $time, i);
  //       end
  //       ERR: begin
  //         assert (~cif.n_clear[i] && cif.index[i] != NO_RULE) 
  //         else   $display("ERROR @ %g: channel %d not clearing the correct rule", $time, i);
  //       end
  //     endcase
  // end

  always @ (negedge clk)
  begin
    for (int i = 1; i < NUM_NFA; i++)
      for (int j = 0; j < N_CB_CHN; j++)
      begin
        if (nif.id[j] == i)
        begin
          if (nif.clear[j] == 1'b1)
          begin
            nif.ready[j] = 1'b0;
            nfa[i].cur_idx = 0;
            nif.match[j] = 1'b0;
            continue;
          end

          if (~nif.ready[j])
          begin
            nif.ready[j] = 1'b1;
            continue;
          end
          else if (nfa[i].pattern[nfa[i].cur_idx] == nif.symbol[j])
            nfa[i].cur_idx += 1;
          
          if (nfa[i].cur_idx >= nfa[i].pattern.len())
            nif.match[j] = 1'b1;
          else
            nif.match[j] = 1'b0;
        end
      end
  end

  initial begin
    for (int i = 0; i < N_CB_CHN; i++)
    begin
      //cif.rule_req[i] = 1'b0;
      //cif.done[i] = 1'b0;
      //cif.rule_id[i] = NO_RULE;
      nif.ready[i] = 1'b0;
      nif.match[i] = 1'b0;
      fif.data = '0;
      fif.rule_id = NO_RULE;
      fif.valid = 1'b0;
    end

    nfa[1].pattern = "AAA";
    nfa[2].pattern = "BBB";

    // *************************************************
    // Reset DUT
    // *************************************************

    test_name = "Reset";
    test_num += 1;

    n_rst = 1'b0;
    @(negedge clk);
    n_rst = 1'b1;

    // *************************************************
    // Matching Pattern
    // *************************************************

    test_name = "Matching Pattern";
    test_num += 1;

    input_data = '0;
    input_data[MAX_PACKET_SIZE-1:0] = "AAAA";
    send_packet(rule_id_t'(1), input_data);

    // *************************************************
    // Non-matching Pattern
    // *************************************************

    for (int i = 0; i < 2; i++)
      @(negedge clk); // give some time for the load balancer to find the lowest capacity

    test_name = "Non-matching Pattern";
    test_num += 1;
    input_data[MAX_PACKET_SIZE-1:0] = "BADB";
    send_packet(rule_id_t'(2), input_data);

    for (int i = 0; i < 100; i++)
      @(negedge clk);

    $finish;

  end

endmodule
`timescale 1 ns/10 ps  // time-unit = 1 ns, precision = 10 ps
//`include "../struct_s.sv"
//`include "./src/full_matcher_types.sv"
////include "./crossbar_if.sv"

module nfa_table_tb; // NOTE: throws "nfa_table not found" unless nfa_table added as directory?

  import full_matcher_types::*;

  // constants
  localparam PERIOD = 10;

  // clk, n_rst
  logic clk, n_rst;
  initial clk = 1'b0;
  // interface
  nfa_if nif();

  // tb signals
  int test_num = 0;
  string test_name = "INIT";

  // DUT
  nfa_table DUT(
    clk,
    n_rst,
    nif
  );

  task automatic process_string;
    input int channel;
    input rule_id_t group;
    input string str;
  begin
    @(negedge clk);
    nif.clear[channel] = 1'b0;
    nif.request[channel] = 1'b1;
    nif.id[channel] = group;
    nif.symbol[channel] = str[0];
    @(negedge clk); // wait for mux pipeline
    while (~nif.ready[channel])
      @(negedge clk);
    for (int i = 0; i < 10; i++) // why so much delay?
      @(negedge clk);
    @(negedge clk);
    @(negedge clk);
    for (int i = 1; i < str.len(); i++)
    begin
      nif.symbol[channel] = symbol_t'(str[i]);
      @(negedge clk);
    end
    for (int i = 0; i < 2; i++) // wait for latch
      @(negedge clk);
    nif.clear[channel] = 1'b1;
    @(negedge clk);
    nif.clear[channel] = 1'b0;
    nif.request[channel] = 1'b0;
  end
  endtask

  // always blocks
  always #(PERIOD/2) clk++;

  initial begin
    for (int i = 0; i < N_CB_CHN; i++)
    begin
      nif.id[i] = NO_RULE;
      nif.symbol[i] = NULL_SYMBOL;
      nif.clear[i] = 1'b1;
      nif.request[i] = 1'b0;
    end

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

    fork
      begin
        for (int i = 0; i < 4; i++)
          @(negedge clk);
        //process_string(0, 1*2, "48c9f4af52d2ad847a2329183b714d8eded9994205a9f58b8167a71c6071");
        process_string(0, 1*2+1, "heello");
      end
      begin
        for (int i = 0; i < 1; i++)
          @(negedge clk);
        //process_string(1, 1*2, "48c9f4ad84ded9994205a9c6071");
        process_string(1, 1*2, "apprehguwkrehstiuwyekthrgregsergregregegregegregrgrgrgr");
      end
      begin
         for (int i = 0; i < 10; i++)
          @(negedge clk);
         //process_string(2, 1*2, "48c9f4af52d2ad847a2329183b714d8eded9994205a9f58b8167a71c6071");
         process_string(2, 1*2, "aeeeefefefefefefefefefeffeffefefeffeb");
      end
    join

    @(negedge clk);
    @(negedge clk);
    @(negedge clk);
    @(negedge clk);
    $finish;

  end

endmodule
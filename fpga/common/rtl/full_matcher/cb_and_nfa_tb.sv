`timescale 1 ns/10 ps  // time-unit = 1 ns, precision = 10 ps
//`include "../struct_s.sv"
//include "./crossbar_if.sv"
//`include "./src/full_matcher_types.sv"

module cb_and_nfa_tb;

  import full_matcher_types::*;

  // constants
  localparam PERIOD = 10;
  localparam NUM_NFA = 1024;
  localparam MAX_CLK = 10000;

  // clk, n_rst
  logic clk, n_rst;
  initial clk = 1'b0;
  // interface
  crossbar_if cif();

  // tb signals
  int test_num = 0;
  string test_name = "INIT";
  int clk_count = 0;
  typedef struct {
    int cur_idx;
    string pattern;
  } nfa_t;
  nfa_t nfa [NUM_NFA-1:0];

  // DUTs
  crossbar DUT_0(
    clk,
    n_rst,
    cif
  );

  nfa_table DUT_1(
    clk,
    n_rst,
    cif
  );

  // Tasks
  task automatic process_rule;
    input int channel;
    input rule_id_t rule_id;
    input string str;
  begin
    request_rule(channel, rule_id, str[0]);
    give_string(channel, str.substr(1,str.len()-1));
    if (cif.nfa_status[channel] == PROC)
      assert_done(channel);
    free_rule(channel);
  end
  endtask

  task automatic request_rule;
    input int channel;
    input rule_id_t rule_id;
    input symbol_t first_symbol;
  begin
    cif.rule_req[channel] = 1'b1;
    cif.rule_id[channel] = rule_id;
    cif.in_symbol[channel] = first_symbol;
    @(negedge clk);
  end
  endtask

  task automatic give_string;
    input int channel;
    input string str;
  begin
    while (cif.nfa_status[channel] != PROC)
      @(negedge clk);
    for (int i = 0; i < str.len(); i++)
    begin
      if (cif.nfa_status[channel] != PROC)
        break;
      cif.in_symbol[channel] = symbol_t'(str[i]);
      @(negedge clk);
    end
  end
  endtask

  task automatic assert_done;
    input int channel;
  begin
    cif.done[channel] = 1'b1;
    @(negedge clk); // because of latching, arb will see FWD one cycle later
    cif.done[channel] = 1'b0;
    @(negedge clk);
  end
  endtask

  task automatic free_rule;
    input int channel;
  begin
    cif.rule_req[channel] = 1'b0;
    cif.rule_id[channel] = NO_RULE;
    cif.in_symbol[channel] = NULL_SYMBOL;
    @(negedge clk);
  end
  endtask

  // always blocks
  always #(PERIOD/2) clk++;

  always @ (negedge clk)
  begin
    for (int i = 0; i < N_CB_CHN; i++)
      for (int j = 0; j < N_CB_CHN; j++)
        if (i != j && cif.index[i] != NO_RULE && cif.index[j] != NO_RULE)
          assert (cif.index[i] != cif.index[j]) 
          else   $display("ERROR @ %g: channel %d's index matches channel %d's index", $time, i, j);
  end

  always @ (negedge clk) // state checking
  begin
    for (int i = 0; i < N_CB_CHN; i++)
      case (cif.nfa_status[i])
        FWD: begin
          assert (~cif.n_clear[i] && cif.index[i] != NO_RULE) 
          else   $display("ERROR @ %g: channel %d not clearing the correct rule", $time, i);
        end
        DROP: begin
          assert (~cif.n_clear[i] && cif.index[i] != NO_RULE) 
          else   $display("ERROR @ %g: channel %d not clearing the correct rule", $time, i);
        end
        ERR: begin
          assert (~cif.n_clear[i] && cif.index[i] != NO_RULE) 
          else   $display("ERROR @ %g: channel %d not clearing the correct rule", $time, i);
        end
      endcase
  end

  always @ (negedge clk)
  begin
    clk_count = clk_count + 1;
    if (clk_count >= MAX_CLK)
      $finish;
  end

  initial begin
    $display("TB Start");
    for (int i = 0; i < N_CB_CHN; i++)
    begin
      cif.rule_req[i] = 1'b0;
      cif.done[i] = 1'b0;
      cif.rule_id[i] = NO_RULE;
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

    fork
    process_rule(0, rule_id_t'(1), "AAA");
    join

    // *************************************************
    // Non-matching Pattern
    // *************************************************

    test_name = "Non-matching Pattern";
    test_num += 1;

    process_rule(0, rule_id_t'(1), "BCBA");

    // *************************************************
    // Request the same rule
    // *************************************************

    test_name = "Request Same Rule";
    test_num += 1;

    // NOTE:
    // tasks have to be AUTOMATIC for the simulator to run more
    // than one instance of the task (lets ths simulator know to
    // allocate the memory instead of it being static)
    fork
        process_rule(0, rule_id_t'(1), "BCBA");
        process_rule(1, rule_id_t'(1), "BCBA");
    join

    // *************************************************
    // Request different rules
    // *************************************************

    test_name = "Request Different Rules";
    test_num += 1;

    fork
        process_rule(0, rule_id_t'(1), "FAAA");
        process_rule(1, rule_id_t'(2), "FBBBB");
    join

    // *************************************************
    // Enter ERR State
    // *************************************************

    test_name = "Enter ERR State";
    test_num += 1;

    // via de-asserting rule_req
    request_rule(0, rule_id_t'(1), "A");
    give_string(0, "A");
    cif.rule_req[0] = 1'b0;
    give_string(0, "A");
    free_rule(0);

    // via changing the rule id
    request_rule(0, rule_id_t'(1), "A");
    give_string(0, "A");
    cif.rule_id[0] = rule_id_t'(99);
    give_string(0, "A");
    free_rule(0);

    $finish;

  end

endmodule
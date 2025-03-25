`timescale 1 ns/10 ps  // time-unit = 1 ns, precision = 10 ps
//`include "./src/struct_s.sv"
//`include "./src/full_matcher_types.sv"
//`include "./full_matcher_if.sv"
////include "./crossbar_if.sv"

module stage_crossing_tb;

  import full_matcher_types::*;

  // constants
  localparam H_PERIOD = 10;
  localparam F_PERIOD = 40;
  localparam NUM_NFA = 1024;

  // clocks, n_rst
  logic h_clk, f_clk, n_rst;
  initial h_clk = 1'b0;
  initial f_clk = 1'b0;
  // interfaces
  full_matcher_if h_fif();
  full_matcher_if f_fif();

  // tb signals
  int test_num = 0;
  string test_name = "INIT";
  logic [MAX_PACKET_SIZE-1:0] input_data;

  // DUT
  stage_crossing DUT (.h_clk, .f_clk, .n_rst, .h_fif, .f_fif);

  // Tasks

  // Tasks
  task automatic send_packet;
    input rule_id_t [7:0] groups;
    input int num_groups;
    input logic [MAX_PACKET_SIZE-1:0] data;
  begin
    h_fif.valid = 1'b1;
    h_fif.last = 1'b0;
    h_fif.data = data;
    for (int i = 0; i < num_groups; i++)
    begin
      h_fif.rule_id = groups[i];
      if (i+1 == num_groups)
        h_fif.last = 1'b1;
      @(negedge h_clk);
    end
    h_fif.last = 1'b0;
    h_fif.valid = 1'b0;
  end
  endtask

  task automatic send_packet_no_deassert;
    input rule_id_t [7:0] groups;
    input int num_groups;
    input logic [MAX_PACKET_SIZE-1:0] data;
  begin
    h_fif.valid = 1'b1;
    h_fif.last = 1'b0;
    h_fif.data = data;
    for (int i = 0; i < num_groups; i++)
    begin
      h_fif.rule_id = groups[i];
      if (i+1 == num_groups)
        h_fif.last = 1'b1;
      @(negedge h_clk);
    end
    h_fif.last = 1'b1;
  end
  endtask

  // always blocks
  always #(H_PERIOD/2) h_clk++;
  always #(F_PERIOD/2) f_clk++;
  

  initial begin
    h_fif.valid = 1'b0;
    h_fif.rule_id = '0;
    h_fif.last = '0;
    h_fif.data = '0;

    // *************************************************
    // Reset DUT
    // *************************************************

    test_name = "Reset";
    test_num += 1;

    n_rst = 1'b1;
    @(negedge h_clk);
    @(negedge f_clk);
    n_rst = 1'b0;
    @(negedge h_clk);
    @(negedge f_clk);
    n_rst = 1'b1;

    // *************************************************
    // Matching Pattern
    // *************************************************

    test_name = "Matching Pattern";
    test_num += 1;

    // TODO: in queue, add counter to initialize BRAM pipeline
    // why is this backwards?
    //  SV too complicated - just used Python to reverse the correct string
    input_data = "1706c17a7618b85f9a5024999dede8d417b3819232a748da2d25fa4f9c84";
    send_packet_no_deassert({rule_id_t'(1*2), rule_id_t'(3*2)}, 2, input_data);

    // *************************************************
    // Non-matching Pattern
    // *************************************************

    //for (int i = 0; i < 2; i++)
    //  @(negedge clk); // give some time for the load balancer to find the lowest capacity

    test_name = "Non-matching Pattern";
    test_num += 1;

    input_data = "1706c17a78da2d25fa4f9c84";
    send_packet_no_deassert({rule_id_t'(3*2), rule_id_t'(3*2+1), rule_id_t'(2*2+1)}, 3, input_data);
    send_packet_no_deassert({rule_id_t'(1*2+1)}, 1, input_data);
    send_packet({rule_id_t'(3*2)}, 1, input_data);
    send_packet({rule_id_t'(2*2)}, 1, input_data);

    //while (fif.data_id_resp != data_id_t'(16'b0000000000000001) || ~fif.valid_resp) // why does this not work?
    for (int i = 0; i < 132; i++)
      @(negedge h_clk);
    @(negedge h_clk);

    input_data = "1706c17a7618b85f9a5024999dede8d417b3819232a748da2d25fa4f9c84";
    send_packet_no_deassert({rule_id_t'(1*2)}, 1, input_data);
    send_packet_no_deassert({rule_id_t'(1*2+1)}, 1, input_data);
    send_packet_no_deassert({rule_id_t'(2*2)}, 1, input_data);
    for (int i = 0; i < 8*N_CB_CHN; i++)
      send_packet_no_deassert({rule_id_t'(2*2+1)}, 1, input_data);
    send_packet({rule_id_t'(3*2)}, 1, input_data);

    for (int i = 0; i < 5000; i++)
      @(negedge h_clk);

    $finish;

  end

endmodule
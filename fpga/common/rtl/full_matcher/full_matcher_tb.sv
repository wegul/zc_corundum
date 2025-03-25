`timescale 1 ns/10 ps  // time-unit = 1 ns, precision = 10 ps
//`include "./src/struct_s.sv"
//`include "./src/full_matcher_types.sv"
//`include "./full_matcher_if.sv"
////include "./crossbar_if.sv"

// Works well with 2 channels

module full_matcher_tb;

  import full_matcher_types::*;

  // constants
  localparam PERIOD = 10;
  localparam NUM_NFA = 1024;

  // clk, n_rst
  logic clk, n_rst;
  initial clk = 1'b0;
  // interfaces
  full_matcher_if fif();

  // tb signals
  int test_num = 0;
  string test_name = "INIT";
  logic [MAX_PACKET_SIZE-1:0] input_data;

  // DUT
  full_matcher DUT (clk, n_rst, fif);

  // Tasks
  task automatic send_packet;
    input rule_id_t [7:0] groups;
    input int num_groups;
    input logic [MAX_PACKET_SIZE-1:0] data;
  begin
    fif.valid = 1'b1;
    fif.last = 1'b0;
    fif.data = data;
    for (int i = 0; i < num_groups; i++)
    begin
      fif.rule_id = groups[i];
      if (i+1 == num_groups)
        fif.last = 1'b1;
      @(negedge clk);
    end
    fif.last = 1'b0;
    fif.valid = 1'b0;
  end
  endtask

  task automatic send_packet_no_deassert;
    input rule_id_t [7:0] groups;
    input int num_groups;
    input logic [MAX_PACKET_SIZE-1:0] data;
  begin
    fif.valid = 1'b1;
    fif.last = 1'b0;
    fif.data = data;
    for (int i = 0; i < num_groups; i++)
    begin
      fif.rule_id = groups[i];
      if (i+1 == num_groups)
        fif.last = 1'b1;
      @(negedge clk);
    end
    fif.last = 1'b1;
  end
  endtask

  // always blocks
  always #(PERIOD/2) clk++;

  initial begin
    for (int i = 0; i < N_CB_CHN; i++)
    begin
      fif.data = '0;
      fif.rule_id = NO_RULE;
      fif.valid = 1'b0;
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
      @(negedge clk);
    @(negedge clk);

    input_data = "1706c17a7618b85f9a5024999dede8d417b3819232a748da2d25fa4f9c84";
    send_packet_no_deassert({rule_id_t'(1*2)}, 1, input_data);
    send_packet_no_deassert({rule_id_t'(1*2+1)}, 1, input_data);
    send_packet_no_deassert({rule_id_t'(2*2)}, 1, input_data);
    for (int i = 0; i < 8*N_CB_CHN; i++)
      send_packet_no_deassert({rule_id_t'(2*2+1), rule_id_t'(3*2)}, 2, input_data);
    send_packet({rule_id_t'(3*2)}, 1, input_data);

    for (int i = 0; i < 5000; i++)
      @(negedge clk);

    $finish;

  end

endmodule
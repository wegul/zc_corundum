module axis_full_matcher_test
(
  aclk,
  fclk,
  rst,
  n_rst
);
  input aclk;
  input fclk;
  input rst;
  input n_rst;

  wire aclk;
  wire fclk;
  wire rst;
  wire n_rst;

  design_1 design_inst (
    .aclk(aclk),
    .fclk(fclk),
    .rst(rst),
    .n_rst(n_rst)
  );
  

endmodule
// NOTE: this is a custom module, add this to the repo

module STE #(parameter integer fan_in = 1)(
           input logic clk,
           input logic run,
           input logic reset,
           input logic [fan_in - 1 : 0] income_edges,
           input logic match,
           output logic active_state);

wire is_potential;
reg internal_reg = 1'b0;

always @ (posedge clk)
begin
    if (reset == 1)
        internal_reg <= 1'b0;
    else if (run == 1)
        internal_reg <= is_potential;
end
assign active_state = internal_reg & match;

assign is_potential = |income_edges;

endmodule
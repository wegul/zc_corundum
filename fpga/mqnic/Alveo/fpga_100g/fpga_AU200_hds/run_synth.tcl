open_project fpga.xpr
reset_run synth_1
launch_runs -jobs 72 synth_1
wait_on_run synth_1

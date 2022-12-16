#from How to use angr on youtube by UT austin

import angr
import claripy

proj = angr.Project("./encrypted_password", main_opts = {"base_addr": 0})
#Becase it is PIE, need to set base_addr to 0; assume PIE offset is zero
#Base address can be adjusted; as long as we know the offsets.
#load_options = {"auto_load_libc" : False}


password_chars = [claripy.BVS("flag_%d" % i,8) for i in range(32)]
#creats an 8 bitvectorsigned that is 32 large; like 32 chars
#can define flaglength like claripy.BVS("flag", 8*flag_length)

password_ast = claripy.Concat(*password_chars)
#password_ast = claripy.Concat(*password_chars + [claripy.BVV(b"\n")])
#this ^^^ is anotherway of doing this - difference is ???

state = proj.factory.entry_state(stdin = password_ast)
#initial entry state 
#state = proj.factory.full_init_state(args = ["./sample", add_options = angr.options.unicorn, stdin = password_ast)
#another way^^^

#optional - add constraints for all characters that are printable if needed
#we typically don't want non printed chars
#for k in password_chars:
#	state.solver.add(k >= ord(!))
#	state.solver.add(k <= ord('~'))

sim_mgr = proj.factory.simulation_manager(state)

sim_mgr.explore(find = 0x940) #with base addr 0 no need to add to values.


if len(sim_mgr.found) > 0:
	print("Solution found")
	found = sim_mgr.found[0]
	found_password = found.solver.eval(password_ast, cast_to=bytes)
	print("%s" % found_password)
	#print(found.posix,dumps(STDIN_FD which is 0 in this case))
	#print(sm.ofund[0].posix.dumps(0).decode("utf-8"))
else:
	print("No solution found")




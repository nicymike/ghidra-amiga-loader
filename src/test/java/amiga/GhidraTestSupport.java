package amiga;

import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.GhidraApplicationLayout;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;

/**
 * Starts Ghidra without a GUI (once per test run) and builds small 68000 programs from machine code.
 */
final class GhidraTestSupport {

	static final String LANGUAGE_68000 = "68000:BE:32:default";

	private GhidraTestSupport() {
	}

	static synchronized void initializeGhidra() throws Exception {
		if (!Application.isInitialized()) {
			ApplicationConfiguration configuration = new ApplicationConfiguration();
			Application.initializeApplication(new GhidraApplicationLayout(), configuration);
		}
	}

	static ProgramBuilder newBuilder() throws Exception {
		initializeGhidra();
		return new ProgramBuilder("test", LANGUAGE_68000);
	}

	static Instruction instructionAt(Program program, long address) {
		return program.getListing().getInstructionAt(program.getAddressFactory().getDefaultAddressSpace().getAddress(address));
	}
}

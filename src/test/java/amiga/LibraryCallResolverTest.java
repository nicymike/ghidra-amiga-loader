package amiga;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Runs the resolver on small hand-assembled 68000 programs. Code is at 0x1000, library names at 0x2000 and
 * 0x2100, the library base variable at 0x3000.
 */
public class LibraryCallResolverTest {

	// movea.l (4).w,a6
	private static final String LOAD_EXEC_BASE = "2C78 0004";
	// lea (0x2000).l,a1 / lea (0x2100).l,a1
	private static final String NAME_DOS = "43F9 0000 2000";
	private static final String NAME_GRAPHICS = "43F9 0000 2100";
	// moveq #0,d0
	private static final String CLEAR_D0 = "7000";
	// moveq #1,d0
	private static final String SET_D0 = "7001";
	// jsr -552(a6): OpenLibrary
	private static final String OPEN_LIBRARY = "4EAE FDD8";
	// jsr -30(a6): any call into the opened library
	private static final String CALL = "4EAE FFE2";
	// move.l d0,(0x3000).l
	private static final String STORE_D0 = "23C0 0000 3000";
	// movea.l (0x3000).l,a6
	private static final String LOAD_VARIABLE = "2C79 0000 3000";
	// movea.l d0,a6
	private static final String D0_TO_A6 = "2C40";
	// movem.l (sp)+,d0/a6
	private static final String RESTORE_REGISTERS = "4CDF 4001";

	private ProgramBuilder builder;
	private Program program;

	@Before
	public void setUp() throws Exception {
		builder = GhidraTestSupport.newBuilder();
		builder.createMemory(".code", "0x1000", 0x100);
		builder.createMemory(".names", "0x2000", 0x200);
		builder.createMemory(".data", "0x3000", 0x10);
		builder.setBytes("0x2000", "64 6F 73 2E 6C 69 62 72 61 72 79 00"); // dos.library
		builder.setBytes("0x2100", "67 72 61 70 68 69 63 73 2E 6C 69 62 72 61 72 79 00"); // graphics.library
		program = builder.getProgram();
	}

	@After
	public void tearDown() {
		builder.dispose();
	}

	/**
	 * Assembles the instructions one after another at 0x1000 and returns the address of the last one.
	 */
	private long load(String... instructions) throws Exception {
		long address = 0x1000;
		long last = address;
		for (var instruction : instructions) {
			builder.setBytes(String.format("0x%x", address), instruction, true);
			last = address;
			address += instruction.replace(" ", "").length() / 2;
		}
		return last;
	}

	private String resolve(long callAddress) {
		var resolver = new LibraryCallResolver(program);
		resolver.scanOpenLibraryCalls(null, TaskMonitor.DUMMY);
		return resolver.resolveLibrary(GhidraTestSupport.instructionAt(program, callAddress));
	}

	@Test
	public void execBaseIsReadFromAddressFour() throws Exception {
		assertEquals("exec_library", resolve(load(LOAD_EXEC_BASE, OPEN_LIBRARY)));
	}

	@Test
	public void libraryBaseFromTheVariableTheResultWasStoredIn() throws Exception {
		var call = load(LOAD_EXEC_BASE, NAME_DOS, CLEAR_D0, OPEN_LIBRARY, STORE_D0, LOAD_VARIABLE, CALL);
		assertEquals("dos_library", resolve(call));
	}

	@Test
	public void libraryBaseDirectlyFromTheOpenLibraryResult() throws Exception {
		var call = load(LOAD_EXEC_BASE, NAME_DOS, CLEAR_D0, OPEN_LIBRARY, D0_TO_A6, CALL);
		assertEquals("dos_library", resolve(call));
	}

	@Test
	public void d0ChangedAfterOpenLibraryIsNotTheLibraryBase() throws Exception {
		var call = load(LOAD_EXEC_BASE, NAME_DOS, CLEAR_D0, OPEN_LIBRARY, SET_D0, D0_TO_A6, CALL);
		assertNull(resolve(call));
	}

	@Test
	public void variableHoldingTwoLibrariesIsAmbiguous() throws Exception {
		var call = load(LOAD_EXEC_BASE, 
			NAME_DOS, CLEAR_D0, OPEN_LIBRARY, STORE_D0, 
			NAME_GRAPHICS, CLEAR_D0, OPEN_LIBRARY, STORE_D0,
			LOAD_VARIABLE, CALL);
		assertNull(resolve(call));
	}

	@Test
	public void a6RestoredFromTheStackIsUnknown() throws Exception {
		// The value that comes back is not the Exec base from before the movem
		var call = load(LOAD_EXEC_BASE, RESTORE_REGISTERS, OPEN_LIBRARY);
		assertNull(resolve(call));
	}

	@Test
	public void callWithoutAnyAssignmentIsUnknown() throws Exception {
		assertNull(resolve(load(OPEN_LIBRARY)));
	}
}

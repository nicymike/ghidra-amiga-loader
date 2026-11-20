package amiga;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.junit.Test;

import ghidra.app.util.Option;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.listing.Program;

public class AmigaUtilsTest {

	@Test
	public void analysisPreparationIsOnByDefault() {
		var option = AmigaUtils.createAssemblyAnalysisOption();
		assertEquals(AmigaUtils.OPTION_ASSEMBLY_ANALYSIS, option.getName());
		assertEquals(Boolean.TRUE, option.getValue());
		// A command line argument is needed to set it in headless mode
		assertEquals("-loader-assemblyAnalysis", option.getArg());
		assertTrue(AmigaUtils.isAssemblyAnalysisEnabled(List.of(option)));
	}

	@Test
	public void preparingTheAnalysisSwitchesOffTheDisturbingAnalyzers() throws Exception {
		var builder = GhidraTestSupport.newBuilder();
		try {
			var program = builder.getProgram();
			var analysisOptions = program.getOptions(Program.ANALYSIS_PROPERTIES);
			// Ghidra's defaults: all four are on
			var names = List.of("Call-Fixup Installer", "Non-Returning Functions - Discovered",
				"Data Reference.Unicode String References", "Reference.Unicode String References");
			int transaction = program.startTransaction("Set analysis defaults");
			for (var name : names) {
				analysisOptions.setBoolean(name, true);
			}
			analysisOptions.setBoolean("Decompiler Parameter ID", true);
			program.endTransaction(transaction, true);

			AmigaUtils.prepareAnalysisForAssembly(program, new MessageLog());

			for (var name : names) {
				assertFalse(name, analysisOptions.getBoolean(name, true));
			}
			// others are left alone
			assertTrue(analysisOptions.getBoolean("Decompiler Parameter ID", false));
		} finally {
			builder.dispose();
		}
	}

	@Test
	public void analysisPreparationCanBeSwitchedOff() {
		var off = Option.newBoolean(AmigaUtils.OPTION_ASSEMBLY_ANALYSIS).value(false).build();
		assertFalse(AmigaUtils.isAssemblyAnalysisEnabled(List.of(Option.newString("ImageBase").value("x").build(), off)));
	}

	@Test
	public void analysisPreparationStaysOnWithoutTheOption() {
		// e.g. when the options come from somewhere that does not know it
		assertTrue(AmigaUtils.isAssemblyAnalysisEnabled(null));
		assertTrue(AmigaUtils.isAssemblyAnalysisEnabled(List.of()));
		assertTrue(AmigaUtils.isAssemblyAnalysisEnabled(List.of(Option.newString("ImageBase").value("x").build())));
	}
}

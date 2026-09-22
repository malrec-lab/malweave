/**
 * This script is derived from the RawByteClf Ghidra scripts and is retained
 * under the upstream MIT license. See LICENSE.RawByteClf.
 *
 * Disable unnecessary analysis options for disassembly.
 *
 * Timing statistics for different analysis engines from 100 files below:
	Decompiler Parameter ID                                646.947 secs
	Decompiler Switch Analysis                             516.444 secs
	Stack                                                  198.839 secs
	x86 Constant Reference Analyzer                        184.340 secs
	Create Address Tables - One Time                       107.247 secs
	Reference                                               80.205 secs
	WindowsResourceReference                                77.761 secs
	Data Reference                                          74.631 secs
	Windows x86 PE Exception Handling                       72.770 secs
	Disassemble                                             59.364 secs
	Function ID                                             47.846 secs
	Apply Data Archives                                     39.304 secs
	Scalar Operand References                               37.058 secs
	Non-Returning Functions - Discovered                    25.425 secs
	Subroutine References                                   25.325 secs
	Create Function                                         25.321 secs
	Windows x86 PE RTTI Analyzer                            22.525 secs
	Call Convention ID                                      18.032 secs
	Decompiler Switch Analysis - One Time                   18.018 secs
	X86 Function Callee Purge                               17.995 secs
	Function Start Search                                   17.293 secs
	Disassemble Entry Points                                13.655 secs
	Create Address Tables                                   12.869 secs
	Shared Return Calls                                     12.676 secs
	ASCII Strings                                           12.220 secs
	Function Start Search After Data                         8.842 secs
	Function Start Search After Code                         6.599 secs
	Demangler Microsoft                                      5.843 secs
	Call-Fixup Installer                                     5.637 secs
	Embedded Media                                           1.559 secs
	Function Start Pre Search                                1.007 secs
	Windows x86 Thread Environment Block (TEB) Analyzer      0.623 secs
	Subroutine References - One Time                         0.563 secs
	Non-Returning Functions - Known                          0.150 secs
	PDB Universal                                            0.132 secs
	Function Start Search delayed - One Time                 0.109 secs
	Demangler GNU                                            0.032 secs
	External Entry References                                0.007 secs
	MinGW Relocations                                        0.005 secs
	Disassemble Entry Points - One Time                      0.004 secs

 * These options have been shown to result in different disassembly instruction streams:
	Decompiler Switch Analysis
    Reference
	x86 Constant Reference Analyzer
	WindowsResourceReference
	Windows x86 PE Exception Handling
	Function ID
*/

import ghidra.app.script.GhidraScript;

import java.util.*;

public class SetAnalysisOptionsForDisassembly extends GhidraScript {

	@Override
	protected void run() throws Exception {

		Map<String, String> options;

		setAnalysisOption(currentProgram, "Decompiler Parameter ID", "false");
		setAnalysisOption(currentProgram, "Stack", "false");

	}

	private void getAndPrintAnalysisOptionsInfo(Map<String, String> options) {

		Map<String, String> optionDescriptions, optionDefaults;

		// Get descriptions associated with the analysis options
		optionDescriptions =
			getAnalysisOptionDescriptions(currentProgram, new ArrayList<String>(options.keySet()));

		// Get default values associated with the analysis options
		optionDefaults =
			getAnalysisOptionDefaultValues(currentProgram, new ArrayList<String>(options.keySet()));

		// Sort analysis options and print out information about each one
		String[] sortedArray = options.keySet().toArray(new String[0]);
		Arrays.sort(sortedArray);

		String[] choicesForOption;
		StringBuilder printStr;
		String defaultVal;

		for (String option : sortedArray) {

			printStr =
				new StringBuilder("[ Option = " + option + " ] [ Description = " +
					optionDescriptions.get(option) + "  ] ");

			// Get choices (if any) that are available for this analysis option
			//choicesForOption = getAnalysisOptionChoices(currentProgram, option);
			choicesForOption = new String[0]; // TODO: above call is deprecated and equates to this.  Fix me.

			if (choicesForOption.length > 0) {
				printStr.append("[ Possible values = { ");

				for (String choice : choicesForOption) {
					printStr.append(" " + choice + " ");
				}
				printStr.append("} ]");
			}

			defaultVal = optionDefaults.get(option);

			if (defaultVal.length() > 0) {
				printStr.append(" [ Default value = " + optionDefaults.get(option) + " ]");
			}

			printStr.append(" [ Current value = " + options.get(option) + " ]");
			println(printStr.toString());
			println("");
		}
	}
}

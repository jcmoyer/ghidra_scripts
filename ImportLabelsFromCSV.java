/**
 * Copyright (c) 2022 J.C. Moyer
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
// Imports labels from a CSV file. The file must be formatted so that each line
// contains `address,name` where `address` is in hexadecimal format. `name`
// should not contain commas.
//@author J.C. Moyer
//@category Import

import java.io.BufferedReader;
import java.io.FileReader;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.SourceType;
import jcmoyer.ghidra_scripts.LabelSet;

public class ImportLabelsFromCSV extends GhidraScript {
    @Override
    public void run() throws Exception {
        var file = askFile("Import labels", "Import");

        LabelSet labels = new LabelSet();
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            labels.loadFromCsv(reader);
        }

        var prog = state.getCurrentProgram();

        int t = prog.startTransaction("import labels");
        boolean success = false;
        try {
            var symTable = prog.getSymbolTable();
            var addrFactory = prog.getAddressFactory();

            for (var label : labels.getLabels()) {
                var addr = addrFactory.getAddress(Long.toHexString(label.getAddress()));
                symTable.createLabel(addr, label.getName(), SourceType.USER_DEFINED);
                printf("create label %s@%x\n", label.getName(), label.getAddress());
            }

            success = true;
        } finally {
            prog.endTransaction(t, success);
        }
    }
}

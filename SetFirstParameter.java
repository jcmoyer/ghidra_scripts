/**
 * Copyright (c) 2023 J.C. Moyer
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
// Sets the first parameter for a range of function pointers. Useful for
// bulk-modifying vtables to take the correct type for "this".
//@author J.C. Moyer
//@category Functions

import java.util.ArrayList;
import java.util.regex.Pattern;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataType;
import ghidra.program.model.symbol.SourceType;

public class SetFirstParameter extends GhidraScript {
    @Override
    public void run() throws Exception {
        var askChangeTo = askString("Parameter type", "Parameter type", "void*");

        var pointerRe = Pattern.compile("^(.*?)\\s*(\\**)$");
        this.println(askChangeTo);
        var pointerM = pointerRe.matcher(askChangeTo);
        if (!pointerM.find()) {
            this.printerr("SetFirstParameter: doesn't look like a valid type: '" + askChangeTo + "'");
            return;
        }
        var typeName = pointerM.group(1);
        var pointers = pointerM.group(2);
        var pointerCount = pointers.length();

        var prog = state.getCurrentProgram();
        var dtm = prog.getDataTypeManager();

        var eligibleTypes = new ArrayList<DataType>();
        dtm.findDataTypes(typeName, eligibleTypes);

        if (eligibleTypes.size() == 0) {
            this.printerr("SetFirstParameter: no eligible types found for '" + askChangeTo + "'");
            return;
        }

        var changeTo = eligibleTypes.get(0);
        for (var i = 0; i < pointerCount; ++i) {
            changeTo = dtm.getPointer(changeTo);
        }

        this.println("SetFirstParameter: using type '" + changeTo.getDisplayName() + "'");

        var t = prog.startTransaction("SetFirstParameter");
        boolean success = false;

        try {
            for (var range : this.currentSelection) {
                for (var addr : range) {
                    var ptr = this.toAddr(this.getLong(addr));
                    var fun = this.getFunctionAt(ptr);
                    if (fun == null) {
                        continue;
                    }
                    this.println(fun.toString());

                    var currentParams = fun.getParameters();
                    currentParams[0].setDataType(changeTo, SourceType.USER_DEFINED);
                }
            }

            success = true;
        } finally {
            prog.endTransaction(t, success);
        }
    }
}

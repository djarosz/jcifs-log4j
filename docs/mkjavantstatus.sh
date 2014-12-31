#!/bin/sh

csvprint -f -s '\t' ntstatus.txt "	public static final int %4 = %1;\n"
echo
echo "	static final int[] NT_STATUS_CODES = {"
csvprint -f -s '\t' ntstatus.txt "		%4,\n"
echo "	};"
echo
echo "	static final String[] NT_STATUS_MESSAGES = {"
csvprint -f -s '\t' ntstatus.txt "		\"%5\",\n"
echo "	};"


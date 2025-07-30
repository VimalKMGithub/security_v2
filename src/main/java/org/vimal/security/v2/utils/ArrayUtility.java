package org.vimal.security.v2.utils;

public class ArrayUtility {
    public static String[] addGivenStringToGivenStringArray(String[] stringArray,
                                                            String stringToAdd) {
        var merged = new String[stringArray.length + 1];
        System.arraycopy(stringArray, 0, merged, 0, stringArray.length);
        merged[stringArray.length] = stringToAdd;
        return merged;
    }

    public static String[] mergeTwoArrays(String[] first,
                                          String[] second) {
        var merged = new String[first.length + second.length];
        System.arraycopy(first, 0, merged, 0, first.length);
        System.arraycopy(second, 0, merged, first.length, second.length);
        return merged;
    }
}

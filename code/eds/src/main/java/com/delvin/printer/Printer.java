package com.delvin.printer;

public class Printer {
    public static void success(String msg) {
        System.out.println(ConsoleColors.GREEN + "[+] " + ConsoleColors.RESET + msg);
    }

    public static void error(String msg) {
        System.out.println(ConsoleColors.RED + "[-] " + ConsoleColors.RESET + msg);
    }

    public static void warning(String msg) {
        System.out.println(ConsoleColors.YELLOW + "[!] " + ConsoleColors.RESET + msg);
    }

    public static void info(String msg) {
        System.out.println("[+] " + msg);
    }
}
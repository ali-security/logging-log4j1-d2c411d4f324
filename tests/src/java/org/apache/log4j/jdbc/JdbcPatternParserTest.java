/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.log4j.jdbc;

import java.util.Arrays;
import java.util.List;

import junit.framework.TestCase;

public class JdbcPatternParserTest extends TestCase {

  String[] EMPTY_STRING_ARRAY = new String[] {};

  public JdbcPatternParserTest(final String name) {
    super(name);
  }

  public void testSingleQuotesAndSpaces() {
    ParserState expected = new ParserState(
        "INSERT INTO A1 (TITLE3) VALUES ( ?, ?, ?, ?,  ?, ? )",
        new String[] {"%d", "%t", "%-5p", " '%c", "%x", "  -  %m%n "});
    assertParserStateEquality(
        "INSERT INTO A1 (TITLE3) VALUES ( '%d', '%t', '%-5p', ' ''%c',  '%x', '  -  %m%n ' )",
        expected);
  }

  public void testWithLiteralsAndSingleQuotes() {
    String prefix = "INSERT INTO A1 (TITLE3) VALUES ( ' aString', 'anotherString with '' xyz'";

    ParserState expected = new ParserState(prefix + ", ?)", new String[] {"message: %m"});
    assertParserStateEquality(prefix + ", 'message: %m')", expected);
  }

  public void testMixedPatterns() {
    ParserState expected = new ParserState(
        "INSERT INTO A1 (TITLE3) VALUES ( ?, ?, ?, ?,  ?, ? )",
        new String[] {"%d", "%d", "%-5p", " %c", "%x", "  -  %m%n"});
    assertParserStateEquality(
        "INSERT INTO A1 (TITLE3) VALUES ( '%d', '%d', '%-5p', ' %c',  '%x', '  -  %m%n' )",
        expected);
  }

  public void testSingleLumpedValue() {
    ParserState expected = new ParserState(
        "INSERT INTO A1 (TITLE3) VALUES ( ? )",
        new String[] {" %d  -  %c %-5p %c %x  -  %m%n "});
    assertParserStateEquality(
        "INSERT INTO A1 (TITLE3) VALUES ( ' %d  -  %c %-5p %c %x  -  %m%n ' )",
        expected);
  }

  /**
   * CVE-2022-23305: conversion patterns are never expanded into the SQL
   * text. Only quoted literals become bind variables; anything outside
   * a quoted literal is kept verbatim and is not formatted with event
   * data.
   */
  public void testUnquotedPatternIsNotExpandedIntoSql() {
    String sql = "INSERT INTO A1 (TITLE3) VALUES ( %m )";
    ParserState expected = new ParserState(sql, EMPTY_STRING_ARRAY);
    assertParserStateEquality(sql, expected);
  }

  private void assertParserStateEquality(String input, ParserState expected) {
    JdbcPatternParser parser = new JdbcPatternParser(input);
    List patternStringReps = parser.getUnmodifiablePatternStringRepresentationList();

    ParserState actual = new ParserState(parser.getParameterizedSql(),
        (String[]) patternStringReps.toArray(EMPTY_STRING_ARRAY));

    assertEquals(expected, actual);
  }

  // this class represents JdbcPatternParser internal state
  private static class ParserState {
    String statementStr;
    String[] args;

    ParserState(String statementStr, String[] args) {
      this.statementStr = statementStr;
      this.args = args;
    }

    public int hashCode() {
      final int prime = 31;
      int result = 1;
      result = prime * result + Arrays.asList(args).hashCode();
      result = prime * result + ((statementStr == null) ? 0 : statementStr.hashCode());
      return result;
    }

    public String toString() {
      return "ParserState [statement=" + statementStr + ", args=" + Arrays.asList(args) + "]";
    }

    public boolean equals(Object obj) {
      if (this == obj)
        return true;
      if (obj == null)
        return false;
      if (getClass() != obj.getClass())
        return false;
      ParserState other = (ParserState) obj;
      if (!Arrays.equals(args, other.args))
        return false;
      if (statementStr == null) {
        if (other.statementStr != null)
          return false;
      } else if (!statementStr.equals(other.statementStr))
        return false;
      return true;
    }
  }
}

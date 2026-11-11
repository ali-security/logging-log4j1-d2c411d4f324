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

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import junit.framework.TestCase;

import org.apache.log4j.Level;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.apache.log4j.MDC;
import org.apache.log4j.NDC;
import org.apache.log4j.PatternLayout;
import org.apache.log4j.PropertyConfigurator;
import org.apache.log4j.VectorErrorHandler;
import org.apache.log4j.xml.XLevel;

public class JdbcAppenderTest extends TestCase {
  private static final String DB_URL = "jdbc:h2:mem:test_db";

  // Closing the last connection to "in-memory h2" removes the database
  // So we keep the connection during the test
  // The logger opens its own connection
  Connection con;

  Logger logger = Logger.getLogger(JdbcAppenderTest.class);

  public JdbcAppenderTest(final String name) {
    super(name);
  }

  public void setUp() throws SQLException {
    try {
      // Explicitly load the H2 driver
      Class.forName("org.h2.Driver");
    } catch (ClassNotFoundException e) {
      throw new RuntimeException("H2 Driver not found in classpath: " + e);
    }

    con = DriverManager.getConnection(DB_URL);
    Statement st = con.createStatement();
    try {
      st.execute(
          "create table logs(level varchar(100),location varchar(100),message varchar(100),message2 varchar(100))");
    } finally {
      st.close();
    }
  }

  public void tearDown() throws SQLException {
    MDC.remove("user");
    NDC.remove();
    LogManager.shutdown();
    con.close();
  }

  public void testVerifyJdbcBufferSize1() throws SQLException {
    PropertyConfigurator.configure("input/jdbc_h2_bufferSize1.properties");

    String oldThreadName = Thread.currentThread().getName();
    try {
      Thread.currentThread().setName("main");
      logger.debug("message with ' quote");
      assertEquals("batchSize=1, so messages should be added immediately",
          "DEBUG; org.apache.log4j.jdbc.JdbcAppenderTest; message with ' quote;  org.apache.log4j.jdbc.JdbcAppenderTest DEBUG message with ' quote\n",
          joinSorted(getMessagesFromDatabase()));

      logger.fatal("message with \" quote");

      assertEquals("batchSize=1, so two messages should be in DB after two logging calls",
          "DEBUG; org.apache.log4j.jdbc.JdbcAppenderTest; message with ' quote;  org.apache.log4j.jdbc.JdbcAppenderTest DEBUG message with ' quote\n"
              + "FATAL; org.apache.log4j.jdbc.JdbcAppenderTest; message with \" quote;  org.apache.log4j.jdbc.JdbcAppenderTest FATAL message with \" quote\n",
          joinSorted(getMessagesFromDatabase()));
    } finally {
      Thread.currentThread().setName(oldThreadName);
    }
  }

  public void testVerifyJdbcBufferSize2() throws SQLException {
    PropertyConfigurator.configure("input/jdbc_h2_bufferSize2.properties");

    String oldThreadName = Thread.currentThread().getName();
    try {
      Thread.currentThread().setName("main");
      logger.log(XLevel.TRACE, "xtrace message");
      logger.debug("message with ' quote");
      logger.info("message with \" quote");
      logger.warn("?");
      // bufferSize=2, so this messsage won't yet be stored to the db
      logger.error("m4");

      assertEquals(
          "DEBUG; org.apache.log4j.jdbc.JdbcAppenderTest; message with ' quote;  org.apache.log4j.jdbc.JdbcAppenderTest DEBUG message with ' quote\n"
              + "INFO; org.apache.log4j.jdbc.JdbcAppenderTest; message with \" quote;  org.apache.log4j.jdbc.JdbcAppenderTest INFO message with \" quote\n"
              + "TRACE; org.apache.log4j.jdbc.JdbcAppenderTest; xtrace message;  org.apache.log4j.jdbc.JdbcAppenderTest TRACE xtrace message\n"
              + "WARN; org.apache.log4j.jdbc.JdbcAppenderTest; ?;  org.apache.log4j.jdbc.JdbcAppenderTest WARN ?\n",
          joinSorted(getMessagesFromDatabase()));

      logger.fatal("m5");

      assertEquals("Logging m5 message should trigger buffer flush for both m4 and m5",
          "DEBUG; org.apache.log4j.jdbc.JdbcAppenderTest; message with ' quote;  org.apache.log4j.jdbc.JdbcAppenderTest DEBUG message with ' quote\n"
              + "ERROR; org.apache.log4j.jdbc.JdbcAppenderTest; m4;  org.apache.log4j.jdbc.JdbcAppenderTest ERROR m4\n"
              + "FATAL; org.apache.log4j.jdbc.JdbcAppenderTest; m5;  org.apache.log4j.jdbc.JdbcAppenderTest FATAL m5\n"
              + "INFO; org.apache.log4j.jdbc.JdbcAppenderTest; message with \" quote;  org.apache.log4j.jdbc.JdbcAppenderTest INFO message with \" quote\n"
              + "TRACE; org.apache.log4j.jdbc.JdbcAppenderTest; xtrace message;  org.apache.log4j.jdbc.JdbcAppenderTest TRACE xtrace message\n"
              + "WARN; org.apache.log4j.jdbc.JdbcAppenderTest; ?;  org.apache.log4j.jdbc.JdbcAppenderTest WARN ?\n",
          joinSorted(getMessagesFromDatabase()));
    } finally {
      Thread.currentThread().setName(oldThreadName);
    }
  }

  /**
   * CVE-2022-23305: a logged message must not be able to alter the
   * structure of the INSERT statement (here: overwrite the value of
   * another column and comment out the rest of the statement).
   */
  public void testMessageCannotInjectColumnValues() throws SQLException {
    PropertyConfigurator.configure("input/jdbc_h2_bufferSize1.properties");

    String payload = "x', 'INJECTED') --";
    logger.debug(payload);

    assertEquals("the malicious message must be stored verbatim",
        "DEBUG; org.apache.log4j.jdbc.JdbcAppenderTest; " + payload
            + ";  org.apache.log4j.jdbc.JdbcAppenderTest DEBUG " + payload + "\n",
        joinSorted(getMessagesFromDatabase()));
  }

  /**
   * CVE-2022-23305: a logged message must not be able to append another
   * SQL statement (here: DROP TABLE) to the INSERT statement.
   */
  public void testMessageCannotInjectStackedStatement() throws SQLException {
    PropertyConfigurator.configure("input/jdbc_h2_bufferSize1.properties");

    String payload = "', ''); drop table logs; --";
    logger.debug(payload);
    logger.info("after");

    // getMessagesFromDatabase() fails if the table has been dropped
    assertEquals("the malicious message must be stored verbatim",
        "DEBUG; org.apache.log4j.jdbc.JdbcAppenderTest; " + payload
            + ";  org.apache.log4j.jdbc.JdbcAppenderTest DEBUG " + payload + "\n"
            + "INFO; org.apache.log4j.jdbc.JdbcAppenderTest; after;  org.apache.log4j.jdbc.JdbcAppenderTest INFO after\n",
        joinSorted(getMessagesFromDatabase()));
  }

  /**
   * CVE-2022-23305: values of the other conversion patterns (MDC, NDC,
   * thread name) are often attacker controlled too and must be bound as
   * parameters as well. Also covers a programmatically configured
   * appender using batch inserts.
   */
  public void testMdcNdcAndThreadNameCannotInjectSql() throws SQLException {
    JDBCAppender appender = new JDBCAppender();
    VectorErrorHandler errorHandler = new VectorErrorHandler();
    appender.setErrorHandler(errorHandler);
    appender.setURL(DB_URL);
    appender.setUser("");
    appender.setPassword("");
    appender.setBufferSize(2);
    appender.setSql(
        "insert into logs(level,location,message,message2) values('%p','%X{user}','%x','%t')");
    appender.activateOptions();

    Logger programmatic = Logger.getLogger("org.apache.log4j.jdbc.programmatic");
    programmatic.setAdditivity(false);
    programmatic.setLevel(Level.ALL);
    programmatic.addAppender(appender);

    String mdcPayload = "u', 'INJ1', 'INJ2') --";
    String ndcPayload = "n'); drop table logs; --";
    String threadPayload = "t' || 'x";

    String oldThreadName = Thread.currentThread().getName();
    try {
      Thread.currentThread().setName(threadPayload);
      MDC.put("user", mdcPayload);
      NDC.push(ndcPayload);
      programmatic.info("first");
      programmatic.warn("second");
    } finally {
      Thread.currentThread().setName(oldThreadName);
    }

    assertEquals("no error expected", 0, errorHandler.size());
    assertEquals("MDC, NDC and thread name must be stored verbatim",
        "INFO; " + mdcPayload + "; " + ndcPayload + "; " + threadPayload + "\n"
            + "WARN; " + mdcPayload + "; " + ndcPayload + "; " + threadPayload + "\n",
        joinSorted(getMessagesFromDatabase()));
  }

  /**
   * CVE-2022-23305: a layout other than PatternLayout cannot be
   * translated into a prepared statement, so nothing must be executed.
   */
  public void testLayoutOtherThanPatternLayoutIsRejected() throws SQLException {
    String sql = "insert into logs(level,location,message,message2) values('%p','%c','%m','%m')";
    JDBCAppender appender = new JDBCAppender();
    VectorErrorHandler errorHandler = new VectorErrorHandler();
    appender.setErrorHandler(errorHandler);
    appender.setURL(DB_URL);
    appender.setUser("");
    appender.setPassword("");
    appender.setSql(sql);
    appender.activateOptions();
    appender.setLayout(new PatternLayout(sql) {
    });

    Logger programmatic = Logger.getLogger("org.apache.log4j.jdbc.customLayout");
    programmatic.setAdditivity(false);
    programmatic.setLevel(Level.ALL);
    programmatic.addAppender(appender);

    programmatic.info("x', 'INJECTED') --");

    assertEquals("nothing must be written with a custom layout",
        "", joinSorted(getMessagesFromDatabase()));
    assertEquals(1, errorHandler.size());
    assertTrue(errorHandler.getException(0) instanceof IllegalArgumentException);
  }

  private static String joinSorted(List list) {
    Collections.sort(list);
    StringBuffer sb = new StringBuffer();
    for (int i = 0; i < list.size(); i++) {
      String s = (String) list.get(i);
      sb.append(s).append('\n');
    }
    return sb.toString();
  }

  private List getMessagesFromDatabase() throws SQLException {
    List res = new ArrayList();
    PreparedStatement ps = con.prepareStatement("select level,location,message,message2 from logs");
    try {
      ResultSet rs = ps.executeQuery();
      try {
        while (rs.next()) {
          res.add(rs.getString(1) + "; " + rs.getString(2) + "; " + rs.getString(3) + "; " + rs.getString(4));
        }
      } finally {
        rs.close();
      }
    } finally {
      ps.close();
    }
    return res;
  }
}

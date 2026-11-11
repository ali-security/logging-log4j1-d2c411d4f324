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

package org.apache.log4j.nt;

import java.io.File;

import org.apache.log4j.AppenderSkeleton;
import org.apache.log4j.Layout;
import org.apache.log4j.TTCCLayout;
import org.apache.log4j.helpers.LogLog;
import org.apache.log4j.spi.LoggingEvent;


/**
   Append to the NT event log system.

   <p><b>WARNING</b> This appender can only be installed and used on a
   Windows system.

   <p>To mitigate DLL hijacking vulnerabilities, set the system property
   <code>log4j.nteventlog.dll.path</code> to the fully qualified absolute
   path of the NTEventLogAppender DLL (e.g.
   <code>-Dlog4j.nteventlog.dll.path=C:\Windows\System32\NTEventLogAppender.amd64.dll</code>).
   When this property is set and points to an existing file, the DLL is loaded
   via {@link System#load(String)} using the absolute path.

   <p>If the property is not set, the appender falls back to
   {@link System#loadLibrary(String)}, which searches the PATH and
   <code>java.library.path</code>. In that case, do not forget to place
   NTEventLogAppender.dll, NTEventLogAppender.amd64.dll,
   NTEventLogAppender.ia64.dll or NTEventLogAppender.x86.dll as appropriate
   in a directory that is on the PATH of the Windows system. Otherwise, you
   will get a java.lang.UnsatisfiedLinkError.

   @author <a href="mailto:cstaylor@pacbell.net">Chris Taylor</a>
   @author <a href="mailto:jim_cakalic@na.biomerieux.com">Jim Cakalic</a> */
public class NTEventLogAppender extends AppenderSkeleton {
  private int _handle = 0;

  private String source = null;
  private String server = null;


  public NTEventLogAppender() {
    this(null, null, null);
  }

  public NTEventLogAppender(String source) {
    this(null, source, null);
  }

  public NTEventLogAppender(String server, String source) {
    this(server, source, null);
  }

  public NTEventLogAppender(Layout layout) {
    this(null, null, layout);
  }

  public NTEventLogAppender(String source, Layout layout) {
    this(null, source, layout);
  }

  public NTEventLogAppender(String server, String source, Layout layout) {
    if (source == null) {
      source = "Log4j";
    }
    if (layout == null) {
      this.layout = new TTCCLayout();
    } else {
      this.layout = layout;
    }

    try {
      _handle = registerEventSource(server, source);
    } catch (Exception e) {
      e.printStackTrace();
      _handle = 0;
    }
  }

  public
  void close() {
    // unregister ...
  }

  public
  void activateOptions() {
    if (source != null) {
      try {
   _handle = registerEventSource(server, source);
      } catch (Exception e) {
   LogLog.error("Could not register event source.", e);
   _handle = 0;
      }
    }
  }


  public void append(LoggingEvent event) {

    StringBuffer sbuf = new StringBuffer();

    sbuf.append(layout.format(event));
    if(layout.ignoresThrowable()) {
      String[] s = event.getThrowableStrRep();
      if (s != null) {
   int len = s.length;
   for(int i = 0; i < len; i++) {
     sbuf.append(s[i]);
   }
      }
    }
    // Normalize the log message level into the supported categories
    int nt_category = event.getLevel().toInt();

    // Anything above FATAL or below DEBUG is labeled as INFO.
    //if (nt_category > FATAL || nt_category < DEBUG) {
    //  nt_category = INFO;
    //}
    reportEvent(_handle, sbuf.toString(), nt_category);
  }


  public
  void finalize() {
    deregisterEventSource(_handle);
    _handle = 0;
  }

  /**
     The <b>Source</b> option which names the source of the event. The
     current value of this constant is <b>Source</b>.
   */
  public
  void setSource(String source) {
    this.source = source.trim();
  }

  public
  String getSource() {
    return source;
  }

/**
     The <code>NTEventLogAppender</code> requires a layout. Hence,
     this method always returns <code>true</code>. */
  public
  boolean requiresLayout() {
    return true;
  }

  native private int registerEventSource(String server, String source);
  native private void reportEvent(int handle, String message, int level);
  native private void deregisterEventSource(int handle);

  static final String DLL_PATH_PROPERTY = "log4j.nteventlog.dll.path";

  /**
   * Resolves the DLL path from the {@value #DLL_PATH_PROPERTY} system property.
   * Returns the absolute path if the property is set and points to an existing
   * file with an absolute path; returns {@code null} otherwise.
   */
  static String resolveConfiguredDllPath() {
      try {
          String dllPath = System.getProperty(DLL_PATH_PROPERTY);
          if (dllPath == null || dllPath.trim().length() == 0) {
              return null;
          }
          dllPath = dllPath.trim();
          File dllFile = new File(dllPath);
          if (!dllFile.isAbsolute()) {
              System.err.println(
                  "Log4j: The path in '" + DLL_PATH_PROPERTY
                  + "' is not absolute: " + dllPath
                  + ". Falling back to library path resolution.");
              return null;
          }
          if (!dllFile.exists()) {
              System.err.println(
                  "Log4j: The file specified in '" + DLL_PATH_PROPERTY
                  + "' does not exist: " + dllPath
                  + ". Falling back to library path resolution.");
              return null;
          }
          return dllFile.getAbsolutePath();
      } catch (SecurityException e) {
          System.err.println(
              "Log4j: Security exception reading '" + DLL_PATH_PROPERTY
              + "'. Falling back to library path resolution.");
          return null;
      }
  }

  static {
      boolean loaded = false;
      try {
          String configuredPath = resolveConfiguredDllPath();
          if (configuredPath != null) {
              System.load(configuredPath);
              loaded = true;
          }
      } catch (UnsatisfiedLinkError e) {
          System.err.println(
              "Log4j: Failed to load NTEventLogAppender DLL from configured path. "
              + "Falling back to library path resolution.");
      } catch (Throwable t) {
          System.err.println(
              "Log4j: Error resolving NTEventLogAppender DLL path. "
              + "Falling back to library path resolution.");
      }

      if (!loaded) {
          String[] archs;
          try {
              archs = new String[] { System.getProperty("os.arch") };
          } catch (SecurityException e) {
              archs = new String[] { "amd64", "ia64", "x86" };
          }
          for (int i = 0; i < archs.length; i++) {
              try {
                  System.loadLibrary("NTEventLogAppender." + archs[i]);
                  loaded = true;
                  break;
              } catch (java.lang.UnsatisfiedLinkError e) {
                  loaded = false;
              }
          }
          if (!loaded) {
              System.loadLibrary("NTEventLogAppender");
          }
      }
  }
}

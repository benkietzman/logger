// vim600: fdm=marker
/* -*- c++ -*- */
///////////////////////////////////////////
// Logger
// -------------------------------------
// file       : logger.cpp
// author     : Ben Kietzman
// begin      : 2014-07-22
// copyright  : kietzman.org
// email      : ben@kietzman.org
///////////////////////////////////////////

/**************************************************************************
*                                                                         *
*   This program is free software; you can redistribute it and/or modify  *
*   it under the terms of the GNU General Public License as published by  *
*   the Free Software Foundation; either version 2 of the License, or     *
*   (at your option) any later version.                                   *
*                                                                         *
**************************************************************************/

/*! \file logger.cpp
* \brief Logger Daemon
*
* Provides a centralized logging service.
*/
// {{{ includes
#include <arpa/inet.h>
#include <bzlib.h>
#include <cerrno>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <openssl/err.h>
#include <openssl/md5.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <pthread.h>
#include <sstream>
#include <string>
#include <sys/syscall.h>
#include <thread>
#include <unistd.h>
#include <zlib.h>
using namespace std;
#include <Central>
#include <Json>
#include <SignalHandling>
using namespace common;
// }}}
// {{{ defines
#ifdef VERSION
#undef VERSION
#endif
/*! \def VERSION
* \brief Contains the application version number.
*/
#define VERSION "0.1"
/*! \def mUSAGE(A)
* \brief Prints the usage statement.
*/
#define mUSAGE(A) cout << endl << "Usage:  "<< A << " [options]"  << endl << endl << " -c, --conf=[CONF]" << endl << "     Provides the configuration path." << endl << endl << " -d, --daemon" << endl << "     Turns the process into a daemon." << endl << endl << "     --data" << endl << "     Sets the data directory." << endl << endl << " -e EMAIL, --email=EMAIL" << endl << "     Provides the email address for default notifications." << endl << endl << " -h, --help" << endl << "     Displays this usage screen." << endl << endl << " -r DAYS, --retain=DAYS" << endl << "     Provides the number of days long-term data should be retained." << endl << endl << " -v, --version" << endl << "     Displays the current version of this software." << endl << endl
/*! \def mVER_USAGE(A,B)
* \brief Prints the version number.
*/
#define mVER_USAGE(A,B) cout << endl << A << " Version: " << B << endl << endl
/*! \def CERTIFICATE
* \brief Contains the certificate path.
*/
#define CERTIFICATE "/server.crt"
/*! \def PID
* \brief Contains the PID path.
*/
#define PID "/.pid"
/*! \def PRIVATE_KEY
* \brief Contains the key path.
*/
#define PRIVATE_KEY "/server.key"
/*! \def SECURE_PORT_MULTI
* \brief Supplies the secure port.
*/
#define SECURE_PORT_MULTI "5649"
/*! \def SECURE_PORT_SINGLE
* \brief Supplies the secure port.
*/
#define SECURE_PORT_SINGLE "5647"
/*! \def STANDARD_PORT_MULTI
* \brief Supplies the standard port.
*/
#define STANDARD_PORT_MULTI "5648"
/*! \def STANDARD_PORT_SINGLE
* \brief Supplies the standard port.
*/
#define STANDARD_PORT_SINGLE "5646"
/*! \def START
* \brief Contains the start path.
*/
#define START "/.start"
/*! \def STORAGE
* \brief Contains the log storage path.
*/
#define STORAGE "/storage"
// }}}
// {{{ structs
struct app
{
  mutex mutexStorage;
  string strApplication;
  string strDataPrefix;
  string strDataSuffix;
  string strIndexPrefix;
  string strIndexSuffix;
  Json *ptAuth;
};
struct feed
{
  list<string> entry;
  map<string, string> criteria;
  string strApplication;
  string strUser;
};
struct parse
{
  map<string, string> *pSearch;
  string *pstrBuffer;
  string strEndTime;
  string strIndex;
  string strData;
  string strStartTime;
  thread threadRequestSearch;
};
// }}}
// {{{ global variables
static bool gbDaemon = false; //!< Global daemon variable.
static bool gbShutdown = false; //!< Global shutdown variable.
static int gnRequests = 0; //!< Contains the number of active requests.
static int gnRetain = 30; //!< Contains the number of days to retain long-term data.
static map<int, feed *> gFeed; //!< Contains the list of feeds.
static map<size_t, app *> gApplication; //!< Contains the index of applications.
static size_t gunRequests = 0; //!< Contains the number requests processed in the last 15 minutes.
static string gstrApplication = "Logger"; //!< Global application name.
static string gstrData = "/data/logger"; //!< Global data path.
static string gstrEmail; //!< Global notification email address.
static string gstrTimezonePrefix = "c"; //!< Contains the local timezone.
static Central *gpCentral = NULL; //!< Contains the Central class.
mutex mutexApplication;
mutex mutexFeed;
mutex mutexRequest;
// }}}
// {{{ prototypes
/*! \fn bool auth(const string strApplication, const string strUser, const string strPassword, const string strFunction, size_t &unID, string &strError, const bool bAdd = false)
* \brief Authorizes an incoming request.
* \param strApplication Contains the application.
* \param strUser Contains the user.
* \param strPassword Contains the password.
* \param strFunction Contains the function.
* \param unID Contains the application ID.
* \param strError Contains the error.
* \param bAdd Contains whether to add a new application entry.
* \return Returns a boolean true/false value.
*/
bool auth(const string strApplication, const string strUser, const string strPassword, const string strFunction, size_t &unID, string &strError, const bool bAdd = false);
/*! \fn void expire()
* \brief Expires data that should no longer be retained.
*/
void expire();
/*! \fn void monitor(string strPrefix)
* \brief Monitors the health of the running process.
*/
void monitor();
/*! \fn void request(SSL_CTX *ctx, int fdSocket, const bool bMulti)
* \brief Maintains communication with client.
* \param ctx Contains the SSL context.
* \param fdSocket Contains the socket handle.
* \param bool bMulti Contains the multi-request value.
*/
void request(SSL_CTX *ctx, int fdSocket, const bool bMulti);
/*! \fn void requestSearch(const size_t unID, map<string, string> s, const string strStartDate, const string strStartTime, const string strEndDate, const string strEndTime, string &strBuffer, bool &bSearch)
* \brief Searches the logs.
* \param unID Contains the application ID.
* \param s Contains the search criteria.
* \param strStartDate Contains the start date.
* \param strStartTime Contains the start time.
* \param strEndDate Contains the end date.
* \param strEndTime Contains the end time.
* \param strBuffer Contains the output buffer.
* \param bSearch Contains the search true/false value.
*/
void requestSearch(const size_t unID, map<string, string> s, const string strStartDate, const string strStartTime, const string strEndDate, const string strEndTime, string &strBuffer, bool &bSearch);
/*! \fn void sighandle(const int nSignal)
* \brief Establishes signal handling for the application.
* \param nSignal Contains the caught signal.
*/
void sighandle(const int nSignal);
/*! \fn bool verify(const string strApplication, const string strUser, const string strPassword, string &strError)
* \brief Authorizes an incoming request.
* \param strApplication Contains the application.
* \param strUser Contains the user.
* \param strPassword Contains the password.
* \param strError Contains the error.
* \return Returns a boolean true/false value.
*/
bool verify(const string strApplication, const string strUser, const string strPassword, string &strError);
// }}}
// {{{ main()
/*! \fn int main(int argc, char *argv[])
* \brief This is the main function.
* \return Exits with a return code for the operating system.
*/
int main(int argc, char *argv[])
{
  string strError, strPrefix = "main()";
  stringstream ssMessage;

  gpCentral = new Central(strError);
  // {{{ set signal handling
  sethandles(sighandle);
  signal(SIGBUS, SIG_IGN);
  signal(SIGCHLD, SIG_IGN);
  signal(SIGPIPE, SIG_IGN);
  signal(SIGSEGV, SIG_IGN);
  signal(SIGWINCH, SIG_IGN);
  // }}}
  // {{{ command line arguments
  for (int i = 1; i < argc; i++)
  {
    string strArg = argv[i];
    if (strArg == "-c" || (strArg.size() > 7 && strArg.substr(0, 7) == "--conf="))
    {
      string strConf;
      if (strArg == "-c" && i + 1 < argc && argv[i+1][0] != '-')
      {
        strConf = argv[++i];
      }
      else
      {
        strConf = strArg.substr(8, strArg.size() - 8);
      }
      gpCentral->manip()->purgeChar(strConf, strConf, "'");
      gpCentral->manip()->purgeChar(strConf, strConf, "\"");
      gpCentral->utility()->setConfPath(strConf, strError);
      gpCentral->acorn()->utility()->setConfPath(strConf, strError);
      gpCentral->junction()->utility()->setConfPath(strConf, strError);
    }
    else if (strArg == "-d" || strArg == "--daemon")
    {
      gbDaemon = true;
    }
    else if (strArg.size() > 7 && strArg.substr(0, 7) == "--data=")
    {
      gstrData = strArg.substr(7, strArg.size() - 7);
      gpCentral->manip()->purgeChar(gstrData, gstrData, "'");
      gpCentral->manip()->purgeChar(gstrData, gstrData, "\"");
    }
    else if (strArg == "-e" || (strArg.size() > 8 && strArg.substr(0, 8) == "--email="))
    {
      if (strArg == "-e" && i + 1 < argc && argv[i+1][0] != '-')
      {
        gstrEmail = argv[++i];
      }
      else
      {
        gstrEmail = strArg.substr(8, strArg.size() - 8);
      }
      gpCentral->manip()->purgeChar(gstrEmail, gstrEmail, "'");
      gpCentral->manip()->purgeChar(gstrEmail, gstrEmail, "\"");
    }
    else if (strArg == "-h" || strArg == "--help")
    {
      mUSAGE(argv[0]);
      return 0;
    }
    else if (strArg == "-r" || (strArg.size() > 9 && strArg.substr(0, 9) == "--retain="))
    {
      string strRetain;
      if (strArg == "-r" && i + 1 < argc && argv[i+1][0] != '-')
      {
        strRetain = argv[++i];
      }
      else
      {
        strRetain = strArg.substr(9, strArg.size() - 9);
      }
      gpCentral->manip()->purgeChar(strRetain, strRetain, "'");
      gpCentral->manip()->purgeChar(strRetain, strRetain, "\"");
      gnRetain = atoi(strRetain.c_str());
    }
    else if (strArg == "-v" || strArg == "--version")
    {
      mVER_USAGE(argv[0], VERSION);
      return 0;
    }
    else
    {
      cout << endl << "Illegal option, '" << strArg << "'." << endl;
      mUSAGE(argv[0]);
      return 0;
    }
  }
  // }}}
  gpCentral->utility()->sslInit();
  gpCentral->acorn()->useSingleSocket(true);
  gpCentral->junction()->useSecureJunction(false);
  gpCentral->junction()->useSingleSocket(true);
  gpCentral->setApplication(gstrApplication);
  gpCentral->setEmail(gstrEmail);
  gpCentral->setLog(gstrData, "logger_", "monthly", true, true);
  gpCentral->setRoom("#nma.system");
  // {{{ normal run
  if (!gstrEmail.empty())
  {
    ifstream inFile;
    map<string, string> credentials;
    if (gbDaemon)
    {
      gpCentral->utility()->daemonize();
    }
    // {{{ determine timezone prefix
    inFile.open("/etc/TIMEZONE");
    if (inFile.good())
    {
      bool bDone = false;
      string strLine;
      while (!bDone && getline(inFile, strLine).good())
      {
        gpCentral->manip()->trim(strLine, strLine);
        if (strLine.size() > 3 && strLine.substr(0, 3) == "TZ=")
        {
          string strTimezone = strLine.substr(3, strLine.size() - 3);
          bDone = true;
          if (strTimezone == "US/Eastern")
          {
            gstrTimezonePrefix = "e";
          }
          else if (strTimezone == "US/Central")
          {
            gstrTimezonePrefix = "c";
          }
          else if (strTimezone == "US/Mountain")
          {
            gstrTimezonePrefix = "m";
          }
          else if (strTimezone == "US/Pacific")
          {
            gstrTimezonePrefix = "p";
          }
        }
      }
    }
    inFile.close();
    // }}}
    //if (gpCentral->utility()->isProcessAlreadyRunning("logger"))
    //{
    //  gbShutdown = true;
    //}
    // {{{ initialize database connections
    inFile.open((gstrData + (string)"/.cred").c_str());
    if (inFile)
    {
      string strLine;
      if (gpCentral->utility()->getLine(inFile, strLine))
      {
        Json *ptCredentials = new Json(strLine);
        ptCredentials->flatten(credentials, true, false);
        delete ptCredentials;
        gpCentral->addDatabase("central", credentials, strError);
      }
    }
    else
    {
      gbShutdown = true;
      ssMessage.str("");
      ssMessage << strPrefix << "->ifstream::open(" << errno << ") error [" << gstrData << "/.cred]:  " << strerror(errno);
      gpCentral->alert(ssMessage.str());
    }
    inFile.close();
    // }}}
    if (!gbShutdown)
    {
      ifstream inApplication;
      ofstream outPid, outStart;
      string strLine;
      SSL_CTX *ctx;
      setlocale(LC_ALL, "");
      outPid.open((gstrData + PID).c_str());
      if (outPid)
      {
        outPid << getpid() << endl;
      }
      outPid.close();
      outStart.open((gstrData + START).c_str());
      outStart.close();
      inApplication.open((gstrData + (string)STORAGE + (string)"/application.index").c_str());
      if (inApplication)
      {
        while (gpCentral->utility()->getLine(inApplication, strLine))
        {
          Json *ptApplication = new Json(strLine);
          for (auto &i : ptApplication->m)
          {
            if (i.second->m.find("n") != i.second->m.end() && !i.second->m["n"]->v.empty() && i.second->m.find("a") != i.second->m.end())
            {
              size_t unID;
              stringstream ssDataPrefix, ssID, ssIndexPrefix;
              app *ptApp = new app;
              ptApp->strApplication = i.second->m["n"]->v;
              ptApp->ptAuth = new Json(i.second->m["a"]);
              for (auto &j : ptApp->ptAuth->m)
              {
                if (!j.second->v.empty())
                {
                  j.second->insert("p", j.second->v);
                  j.second->insert("t", ((j.first == "logger")?"f":"r"));
                }
              }
              ssDataPrefix << gstrData << STORAGE << "/" << i.first << "-";
              ptApp->strDataPrefix = ssDataPrefix.str();
              ptApp->strDataSuffix = ".data";
              ssIndexPrefix << gstrData << STORAGE << "/" << i.first << "-";
              ptApp->strIndexPrefix = ssIndexPrefix.str();
              ptApp->strIndexSuffix = ".index";
              ssID.str(i.first);
              ssID >> unID;
              gApplication[unID] = ptApp;
            }
          }
          delete ptApplication;
        }
      }
      else
      {
        ssMessage.str("");
        ssMessage << strPrefix << "->ifstream::open(" << errno << ") error [" << gstrData << STORAGE << "/application.index]:  " << strerror(errno);
        gpCentral->notify(ssMessage.str());
      }
      inApplication.close();
      thread threadExpire(expire);
      pthread_setname_np(threadExpire.native_handle(), "expire");
      thread threadMonitor(monitor);
      pthread_setname_np(threadMonitor.native_handle(), "monitor");
      if ((ctx = gpCentral->utility()->sslInitServer((gstrData + CERTIFICATE), (gstrData + PRIVATE_KEY), strError)) != NULL)
      {
        ssMessage.str("");
        ssMessage << strPrefix << "->CentralAddons::utility()->sslInitServer():  SSL initialization was successful.";
        gpCentral->log(ssMessage.str());
      }
      else
      {
        gbShutdown = true;
        ssMessage.str("");
        ssMessage << strPrefix << "->CentralAddons::utility()->sslInitServer() error:  " << strError;
        gpCentral->notify(ssMessage.str());
      }
      if (!gbShutdown)
      {
        bool bListen[4][4];
        int fdSocket[4], nReturn;
        for (size_t i = 0; i < 4; i++)
        {
          addrinfo hints, *result;
          memset(&hints, 0, sizeof(struct addrinfo));
          hints.ai_family = AF_INET6;
          hints.ai_socktype = SOCK_STREAM;
          hints.ai_flags = AI_PASSIVE;
          bListen[i][0] = bListen[i][1] = bListen[i][2] = bListen[i][3] = false;
          if ((nReturn = getaddrinfo(NULL, ((i == 0)?STANDARD_PORT_SINGLE:((i == 1)?SECURE_PORT_SINGLE:((i == 2)?STANDARD_PORT_MULTI:SECURE_PORT_MULTI))), &hints, &result)) == 0)
          {
            struct addrinfo *rp;
            bListen[i][0] = true;
            for (rp = result; !bListen[i][2] && rp != NULL; rp = rp->ai_next)
            {
              bListen[i][1] = bListen[i][2] = false;
              if ((fdSocket[i] = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol)) >= 0)
              {
                int nOn = 1;
                bListen[i][1] = true;
                setsockopt(fdSocket[i], SOL_SOCKET, SO_REUSEADDR, (char *)&nOn, sizeof(nOn));
                if (bind(fdSocket[i], rp->ai_addr, rp->ai_addrlen) == 0)
                {
                  bListen[i][2] = true;
                  if (listen(fdSocket[i], SOMAXCONN) == 0)
                  {
                    bListen[i][3] = true;
                  }
                  else
                  {
                    close(fdSocket[i]);
                  }
                }
                else
                {
                  close(fdSocket[i]);
                }
              }
            }
            freeaddrinfo(result);
          }
        }
        if (bListen[0][3] && bListen[1][3] && bListen[2][3] && bListen[3][3])
        {
          ssMessage.str("");
          ssMessage << strPrefix << "->listen():  Listening to socket.";
          gpCentral->log(ssMessage.str());
          while (!gbShutdown)
          {
            pollfd fds[4];
            fds[0].fd = fdSocket[0];
            fds[0].events = POLLIN;
            fds[1].fd = fdSocket[1];
            fds[1].events = POLLIN;
            fds[2].fd = fdSocket[2];
            fds[2].events = POLLIN;
            fds[3].fd = fdSocket[3];
            fds[3].events = POLLIN;
            if ((nReturn = poll(fds, 4, 2000)) > 0)
            {
              int fdData;
              sockaddr_in cli_addr;
              socklen_t clilen = sizeof(cli_addr);
              if (fds[0].fd == fdSocket[0] && (fds[0].revents & POLLIN))
              {
                if ((fdData = accept(fdSocket[0], (struct sockaddr *)&cli_addr, &clilen)) >= 0)
                {
                  thread tThread(request, (SSL_CTX *)NULL, fdData, false);
                  pthread_setname_np(tThread.native_handle(), "request");
                  tThread.detach();
                }
                else
                {
                  gbShutdown = true;
                  ssMessage.str("");
                  ssMessage << strPrefix << "->accept(" << errno << ") error:  " << strerror(errno);
                  gpCentral->alert(ssMessage.str());
                }
              }
              if (fds[1].fd == fdSocket[1] && (fds[1].revents & POLLIN))
              {
                if ((fdData = accept(fdSocket[1], (struct sockaddr *)&cli_addr, &clilen)) >= 0)
                {
                  thread tThread(request, ctx, fdData, false);
                  pthread_setname_np(tThread.native_handle(), "request");
                  tThread.detach();
                }
                else
                {
                  gbShutdown = true;
                  ssMessage.str("");
                  ssMessage << strPrefix << "->accept(" << errno << ") error:  " << strerror(errno);
                  gpCentral->alert(ssMessage.str());
                }
              }
              if (fds[2].fd == fdSocket[2] && (fds[2].revents & POLLIN))
              {
                if ((fdData = accept(fdSocket[2], (struct sockaddr *)&cli_addr, &clilen)) >= 0)
                {
                  thread tThread(request, (SSL_CTX *)NULL, fdData, true);
                  pthread_setname_np(tThread.native_handle(), "request");
                  tThread.detach();
                }
                else
                {
                  gbShutdown = true;
                  ssMessage.str("");
                  ssMessage << strPrefix << "->accept(" << errno << ") error:  " << strerror(errno);
                  gpCentral->alert(ssMessage.str());
                }
              }
              if (fds[3].fd == fdSocket[3] && (fds[3].revents & POLLIN))
              {
                if ((fdData = accept(fdSocket[3], (struct sockaddr *)&cli_addr, &clilen)) >= 0)
                {
                  thread tThread(request, ctx, fdData, true);
                  pthread_setname_np(tThread.native_handle(), "request");
                  tThread.detach();
                }
                else
                {
                  gbShutdown = true;
                  ssMessage.str("");
                  ssMessage << strPrefix << "->accept(" << errno << ") error:  " << strerror(errno);
                  gpCentral->alert(ssMessage.str());
                }
              }
            }
            else if (nReturn < 0)
            {
              gbShutdown = true;
              ssMessage.str("");
              ssMessage << strPrefix << "->poll(" << errno << ") error:  " << strerror(errno);
              gpCentral->alert(ssMessage.str());
            }
          }
          close(fdSocket[0]);
          close(fdSocket[1]);
          close(fdSocket[2]);
          close(fdSocket[3]);
          ssMessage.str("");
          ssMessage << strPrefix << "->close():  Closed socket.";
          gpCentral->log(ssMessage.str());
        }
        else if (!bListen[0][0] || (bListen[0][3] && !bListen[1][0]) || (bListen[0][3] && bListen[1][3] && !bListen[2][0]) || (bListen[0][3] && bListen[1][3] && bListen[2][3] && !bListen[3][0]))
        {
          ssMessage.str("");
          ssMessage << strPrefix << "->getaddrinfo(" << nReturn << ") error:  " << gai_strerror(nReturn);
          gpCentral->alert(ssMessage.str());
        }
        else
        {
          ssMessage.str("");
          ssMessage << strPrefix << "->" << ((!bListen[0][1] || (bListen[0][3] && !bListen[1][1]) || (bListen[0][3] && bListen[1][3] && !bListen[2][1]) || (bListen[0][3] && bListen[1][3] && bListen[2][3] && !bListen[3][1]))?"socket":((!bListen[0][2] || (bListen[0][3] && !bListen[1][2]) || (bListen[0][3] && bListen[1][3] && !bListen[2][2]) || (bListen[0][3] && bListen[1][3] && bListen[2][3] && !bListen[3][2]))?"bind":"listen")) << "(" << errno << ") error:  " << strerror(errno);
          gpCentral->alert(ssMessage.str());
        }
      }
      threadExpire.join();
      threadMonitor.join();
      while (gnRequests > 0)
      {
        gpCentral->utility()->msleep(250);
      }
      for (auto &i : gApplication)
      {
        delete i.second->ptAuth;
        i.second->strApplication.clear();
        i.second->strDataPrefix.clear();
        i.second->strDataSuffix.clear();
        i.second->strIndexPrefix.clear();
        i.second->strIndexSuffix.clear();
        delete i.second;
      }
      gApplication.clear();
      SSL_CTX_free(ctx);
      // {{{ check pid file
      if (gpCentral->file()->fileExist(gstrData + PID))
      {
        gpCentral->file()->remove(gstrData + PID);
      }
      // }}}
    }
  }
  // }}}
  // {{{ usage statement
  else
  {
    mUSAGE(argv[0]);
  }
  // }}}
  gpCentral->utility()->sslDeinit();
  delete gpCentral;

  return 0;
}
// }}}
// {{{ auth()
bool auth(const string strApplication, const string strUser, const string strPassword, const string strFunction, size_t &unID, string &strError, const bool bAdd)
{
  bool bFoundApplication = false, bResult = false, bUpdate = false;
  string strPrefix = "auth()";
  stringstream ssMessage, ssQuery;

  mutexApplication.lock();
  for (auto &i : gApplication)
  {
    if (i.second->strApplication == strApplication)
    {
      bFoundApplication = true;
      unID = i.first;
    }
  }
  if (!bFoundApplication)
  {
    ssQuery.str("");
    ssQuery << "select id from application where name = '" << strApplication << "'";
    list<map<string, string> > *getApplication = gpCentral->query("central", ssQuery.str(), strError);
    if (getApplication != NULL)
    {
      if (!getApplication->empty())
      {
        map<string, string> getApplicationRow = getApplication->front();
        stringstream ssID;
        ssID.str(getApplicationRow["id"]);
        ssID >> unID;
        if (gApplication.find(unID) != gApplication.end())
        {
          bFoundApplication = bUpdate = true;
          gApplication[unID]->strApplication = strApplication;
        }
        else if (bAdd)
        {
          ssQuery.str("");
          ssQuery << "select b.type from application_account a, account_type b where a.type_id = b.id and a.application_id = " << unID << " and a.user_id = '" << strUser << "'";
          list<map<string, string> > *getAccountType = gpCentral->query("central", ssQuery.str(), strError);
          if (getAccountType != NULL)
          {
            if (!getAccountType->empty())
            {
              map<string, string> getAccountTypeRow = getAccountType->front();
              if (getAccountTypeRow["type"] == "Logger" || getAccountTypeRow["type"] == "Logger - read" || getAccountTypeRow["type"] == "Logger - write")
              {
                if (verify(strApplication, strUser, strPassword, strError))
                {
                  stringstream ssDataPrefix, ssIndexPrefix;
                  bFoundApplication = bUpdate = true;
                  gApplication[unID] = new app;
                  gApplication[unID]->ptAuth = new Json;
                  gApplication[unID]->ptAuth->m[strUser] = new Json;
                  gApplication[unID]->ptAuth->m[strUser]->insert("p", strPassword);
                  gApplication[unID]->ptAuth->m[strUser]->insert("t", ((getAccountTypeRow["type"] == "Logger")?"f":((getAccountTypeRow["type"] == "Logger - read")?"r":"w")));
                  gApplication[unID]->strApplication = strApplication;
                  ssDataPrefix << gstrData << STORAGE << "/" << unID << "-";
                  gApplication[unID]->strDataPrefix = ssDataPrefix.str();
                  gApplication[unID]->strDataSuffix = ".data";
                  ssIndexPrefix << gstrData << STORAGE << "/" << unID << "-";
                  gApplication[unID]->strIndexPrefix = ssIndexPrefix.str();
                  gApplication[unID]->strIndexSuffix = ".index";
                  if (gApplication[unID]->ptAuth->m[strUser]->m["t"]->v == "f" || ((strFunction == "feed" || strFunction == "search") && gApplication[unID]->ptAuth->m[strUser]->m["t"]->v == "r") || ((strFunction == "log" || strFunction == "message") && gApplication[unID]->ptAuth->m[strUser]->m["t"]->v == "w"))
                  {
                    bResult = true;
                  }
                  else
                  {
                    strError = "Function being requested does not match authority of Account Type.";
                  }
                }
              }
              else
              {
                strError = "Please register a valid Account Type:  Logger, Logger - read, Logger - write.";
              }
              getAccountTypeRow.clear();
            }
            else
            {
              strError = "Failed to locate Account Type.";
            }
          }
          gpCentral->free(getAccountType);
        }
        else
        {
          strError = "Application not registered in Logger.";
        }
        getApplicationRow.clear();
      }
      else
      {
        strError = "Please provide a valid Application.";
      }
    }
    gpCentral->free(getApplication);
  }
  if (bFoundApplication && !bResult)
  {
    if (gApplication[unID]->ptAuth->m.find(strUser) != gApplication[unID]->ptAuth->m.end())
    {
      if (gApplication[unID]->ptAuth->m[strUser]->m.find("p") != gApplication[unID]->ptAuth->m[strUser]->m.end() && gApplication[unID]->ptAuth->m[strUser]->m["p"]->v == strPassword)
      {
        bResult = true;
      }
      else if (verify(strApplication, strUser, strPassword, strError))
      {
        bResult = bUpdate = true;
        gApplication[unID]->ptAuth->m[strUser]->insert("p", strPassword);
      }
      if (bResult)
      {
        bResult = false;
        if (gApplication[unID]->ptAuth->m[strUser]->m["t"]->v == "f" || ((strFunction == "feed" || strFunction == "search") && gApplication[unID]->ptAuth->m[strUser]->m["t"]->v == "r") || ((strFunction == "log" || strFunction == "message") && gApplication[unID]->ptAuth->m[strUser]->m["t"]->v == "w"))
        {
          bResult = true;
        }
        else
        {
          ssQuery.str("");
          ssQuery << "select b.type from application_account a, account_type b where a.type_id = b.id and a.application_id = " << unID << " and a.user_id = '" << strUser << "'";
          list<map<string, string> > *getAccountType = gpCentral->query("central", ssQuery.str(), strError);
          if (getAccountType != NULL)
          {
            bUpdate = true;
            if (!getAccountType->empty())
            {
              map<string, string> getAccountTypeRow = getAccountType->front();
              if (getAccountTypeRow["type"] == "Logger" || getAccountTypeRow["type"] == "Logger - read" || getAccountTypeRow["type"] == "Logger - write")
              {
                gApplication[unID]->ptAuth->m[strUser]->insert("t", ((getAccountTypeRow["type"] == "Logger")?"f":((getAccountTypeRow["type"] == "Logger - read")?"r":"w")));
                if (gApplication[unID]->ptAuth->m[strUser]->m["t"]->v == "f" || ((strFunction == "feed" || strFunction == "search") && gApplication[unID]->ptAuth->m[strUser]->m["t"]->v == "r") || ((strFunction == "log" || strFunction == "message") && gApplication[unID]->ptAuth->m[strUser]->m["t"]->v == "w"))
                {
                  bResult = true;
                }
                else
                {
                  strError = "Function being requested does not match authority of Account Type.";
                }
              }
              else
              {
                strError = "Please register a valid Account Type:  Logger, Logger - read, Logger - write.";
                delete gApplication[unID]->ptAuth->m[strUser];
                gApplication[unID]->ptAuth->m.erase(strUser);
              }
              getAccountTypeRow.clear();
            }
            else
            {
              strError = "Failed to locate Account Type.";
              delete gApplication[unID]->ptAuth->m[strUser];
              gApplication[unID]->ptAuth->m.erase(strUser);
            }
          }
          gpCentral->free(getAccountType);
        }
      }
    }
    else if (verify(strApplication, strUser, strPassword, strError))
    {
      ssQuery.str("");
      ssQuery << "select b.type from application_account a, account_type b where a.type_id = b.id and a.application_id = " << unID << " and a.user_id = '" << strUser << "'";
      list<map<string, string> > *getAccountType = gpCentral->query("central", ssQuery.str(), strError);
      if (getAccountType != NULL)
      {
        if (!getAccountType->empty())
        {
          map<string, string> getAccountTypeRow = getAccountType->front();
          if (getAccountTypeRow["type"] == "Logger" || getAccountTypeRow["type"] == "Logger - read" || getAccountTypeRow["type"] == "Logger - write")
          {
            bUpdate = true;
            gApplication[unID]->ptAuth->m[strUser] = new Json;
            gApplication[unID]->ptAuth->m[strUser]->insert("p", strPassword);
            gApplication[unID]->ptAuth->m[strUser]->insert("t", ((getAccountTypeRow["type"] == "Logger")?"f":((getAccountTypeRow["type"] == "Logger - read")?"r":"w")));
            if (gApplication[unID]->ptAuth->m[strUser]->m["t"]->v == "f" || ((strFunction == "feed" || strFunction == "search") && gApplication[unID]->ptAuth->m[strUser]->m["t"]->v == "r") || ((strFunction == "log" || strFunction == "message") && gApplication[unID]->ptAuth->m[strUser]->m["t"]->v == "w"))
            {
              bResult = true;
            }
          }
          else
          {
            strError = "Please register a valid Account Type:  Logger, Logger - read, Logger - write.";
          }
          getAccountTypeRow.clear();
        }
        else
        {
          strError = "Failed to locate Account Type.";
        }
      }
    }
  }
  if (bUpdate)
  {
    ofstream outApplication((gstrData + (string)STORAGE + (string)"/application.index").c_str());
    if (outApplication)
    {
      for (auto &i : gApplication)
      {
        string strID;
        stringstream ssID;
        Json *ptApplication = new Json;
        ssID << i.first;
        strID = ssID.str();
        ptApplication->m[strID] = new Json;
        ptApplication->m[strID]->insert("n", i.second->strApplication);
        ptApplication->m[strID]->insert("a", i.second->ptAuth);
        outApplication << ptApplication << endl;
        delete ptApplication;
      }
    }
    else
    {
      ssMessage.str("");
      ssMessage << "Internal Error:  auth()->ofstream::open(" << errno << ") [" << gstrData << STORAGE << "/application.index]:  " << strerror(errno);
      strError = ssMessage.str();
    }
    outApplication.close();
  }
  mutexApplication.unlock();

  return bResult;
}
// }}}
// {{{ expire()
void expire()
{
  string strError, strPrefix = "expire()";
  stringstream ssMessage;

  while (!gbShutdown)
  {
    int nYear, nMonth, nDay;
    list<string> dir;
    stringstream ssDate;
    gpCentral->date()->getYear(nYear);
    gpCentral->date()->getMonth(nMonth);
    gpCentral->date()->getDay(nDay);
    gpCentral->date()->addDays(nYear, nMonth, nDay, (gnRetain * (-1)));
    ssDate << setw(4) << setfill('0') << nYear;
    ssDate << setw(2) << setfill('0') << nMonth;
    ssDate << setw(2) << setfill('0') << nDay;
    gpCentral->file()->directoryList(gstrData + (string)STORAGE, dir);
    for (auto &i : dir)
    {
      size_t unPosition[2];
      if (i.size() > 10 && (unPosition[0] = i.find("-")) != string::npos && (unPosition[1] = i.find(".", unPosition[0])) != string::npos && i.substr(unPosition[0] + 1, unPosition[1] - (unPosition[0] + 1)) < ssDate.str())
      {
        stringstream ssFile;
        ssFile << gstrData << STORAGE << "/" << i;
        if (gpCentral->file()->remove(ssFile.str()))
        {
          ssMessage.str("");
          ssMessage << strPrefix << "->Central::file()->remove() [" << ssFile.str() << "]:  Removed expired file.";
          gpCentral->log(ssMessage.str());
        }
        else
        {
          ssMessage.str("");
          ssMessage << strPrefix << "->Central::file()->remove(" << errno << ") [" << ssFile.str() << "] error:  " << strerror(errno);
          gpCentral->notify(ssMessage.str());
        }
      }
    }
    dir.clear();
    for (size_t i = 0; !gbShutdown && i < 345600; i++)
    {
      gpCentral->utility()->msleep(250);
    }
  }
}
// }}}
// {{{ monitor()
void monitor()
{
  float fCpu, fMem;
  string strError, strPrefix = "monitor()";
  time_t CTime;
  unsigned int unCount = 0;
  unsigned long ulMaxResident = 1024 * 1024 * 50, ulImage, ulResident;

  while (!gbShutdown)
  {
    gpCentral->getProcessStatus(CTime, fCpu, fMem, ulImage, ulResident);
    if (ulResident >= ulMaxResident)
    {
      stringstream ssMessage;
      ssMessage << strPrefix << ":  The logger daemon has a resident size of " << ulResident << " KB which exceeds the maximum resident restriction of " << ulMaxResident << " KB.  Restarting process.";
      gpCentral->notify(ssMessage.str());
      gbShutdown = true;
      sighandle(SIGTERM);
    }
    if (!gbShutdown)
    {
      if (unCount++ >= 15)
      {
        stringstream ssMessage;
        unCount = 0;
        ssMessage.str("");
        mutexRequest.lock();
        ssMessage << strPrefix << ":  " << gunRequests << " requests were processed in the last 15 minutes.";
        gunRequests = 0;
        mutexRequest.unlock();
        gpCentral->log(ssMessage.str());
        ssMessage.str("");
        ssMessage << strPrefix << ":  Resident size is " << ulResident << ".";
        gpCentral->log(ssMessage.str());
      }
      for (size_t i = 0; !gbShutdown && i < 240; i++)
      {
        gpCentral->utility()->msleep(250);
      }
    }
  }
}
// }}}
// {{{ request()
void request(SSL_CTX *ctx, int fdSocket, const bool bMulti)
{
  bool bSecure = ((ctx != NULL)?true:false);
  SSL *ssl = NULL;
  string strError, strPrefix;
  stringstream ssMessage, ssPrefix;

  ssPrefix << "request(" << syscall(SYS_gettid) << ")";
  strPrefix = ssPrefix.str();
  mutexRequest.lock();
  gnRequests++;
  mutexRequest.unlock();
  ERR_clear_error();
  if (!bSecure || (ssl = SSL_new(ctx)) != NULL)
  {
    if (!bSecure || SSL_set_fd(ssl, fdSocket) == 1)
    {
      int nReturn;
      if (!bSecure || (nReturn = SSL_accept(ssl)) == 1)
      {
        bool bExit = false, bSearch = false;
        size_t unPosition;
        string strApplication, strBuffer[2], strFunction, strSearch;
        thread *pThreadSearch = NULL;
        feed *ptFeed = NULL;
        while (!bExit)
        {
          pollfd fds[1];
          fds[0].fd = fdSocket;
          fds[0].events = POLLIN;
          if (ptFeed != NULL)
          {
            while (!ptFeed->entry.empty())
            {
              strBuffer[1].append(ptFeed->entry.front());
              strBuffer[1].append("\n");
              ptFeed->entry.pop_front();
            }
          }
          if (!strBuffer[1].empty())
          {
            fds[0].events |= POLLOUT;
          }
          if ((nReturn = poll(fds, 1, 250)) > 0)
          {
            // {{{ read
            if (fds[0].fd == fdSocket && (fds[0].revents & POLLIN))
            {
              if ((!bSecure && gpCentral->utility()->fdRead(fdSocket, strBuffer[0], nReturn)) || (bSecure && gpCentral->utility()->sslRead(ssl, strBuffer[0], nReturn)))
              {
                while ((unPosition = strBuffer[0].find("\n")) != string::npos)
                {
                  bool bProcessed = false, bWrote = false;
                  string strResponse;
                  stringstream ssDate;
                  struct tm tTime;
                  time_t CTime;
                  Json *ptRequest = new Json(strBuffer[0].substr(0, unPosition));
                  time(&CTime);
                  localtime_r(&CTime, &tTime);
                  ssDate << setw(4) << setfill('0') << (tTime.tm_year + 1900);
                  ssDate << setw(2) << setfill('0') << (tTime.tm_mon + 1);
                  ssDate << setw(2) << setfill('0') << tTime.tm_mday;
                  strBuffer[0].erase(0, unPosition + 1);
                  if (ptRequest->m.find("Application") != ptRequest->m.end() && !ptRequest->m["Application"]->v.empty())
                  {
                    strApplication = ptRequest->m["Application"]->v;
                    if (ptRequest->m.find("User") != ptRequest->m.end() && !ptRequest->m["User"]->v.empty())
                    {
                      if (ptRequest->m.find("Password") != ptRequest->m.end() && !ptRequest->m["Password"]->v.empty())
                      {
                        if (ptRequest->m.find("Function") != ptRequest->m.end() && !ptRequest->m["Function"]->v.empty())
                        {
                          strFunction = ptRequest->m["Function"]->v;
                          if (strFunction == "feed" || strFunction == "search")
                          {
                            Json *ptJson = new Json(ptRequest);
                            if (ptJson->m.find("Password") != ptJson->m.end())
                            {
                              ptJson->m["Password"]->v = "******";
                            }
                            ssMessage.str("");
                            ssMessage << strPrefix << " [" << strFunction << " request " << fdSocket << "]:  " << ptJson;
                            gpCentral->log(ssMessage.str());
                            delete ptJson;
                          }
                          // {{{ Function:  feed
                          if (strFunction == "feed")
                          {
                            if (!bMulti)
                            {
                              size_t unID;
                              if (auth(strApplication, ptRequest->m["User"]->v, ptRequest->m["Password"]->v, strFunction, unID, strError))
                              {
                                if (ptRequest->m.find("Search") != ptRequest->m.end())
                                {
                                  mutexFeed.lock();
                                  if (gFeed.find(fdSocket) == gFeed.end())
                                  {
                                    ptFeed = new feed;
                                    ptFeed->strApplication = strApplication;
                                    ptFeed->strUser = ptRequest->m["User"]->v;
                                    ptRequest->m["Search"]->flatten(ptFeed->criteria, false, false);
                                    gFeed[fdSocket] = ptFeed;
                                    bProcessed = bWrote = true;
                                    mutexRequest.lock();
                                    gunRequests++;
                                    mutexRequest.unlock();
                                    ptRequest->insert("Status", "okay");
                                    ptRequest->json(strResponse);
                                    strBuffer[1].append(strResponse);
                                    strBuffer[1].append("\n");
                                  }
                                  else
                                  {
                                    ssMessage.str("");
                                    ssMessage << "Internal Error:  request()->feed [" << fdSocket << "]:  Socket file descriptor already used in global feed list.";
                                    ptRequest->insert("Error", ssMessage.str());
                                  }
                                  mutexFeed.unlock();
                                }
                                else
                                {
                                  ptRequest->insert("Error", "Please provide the Search.");
                                }
                              }
                              else
                              {
                                ptRequest->insert("Error", strError);
                              }
                            }
                            else
                            {
                              ptRequest->insert("Error", "The feed Function may not be requested on a multi-request port.");
                            }
                          }
                          // }}}
                          // {{{ Function:  log or message
                          else if (strFunction == "log" || strFunction == "message")
                          {
                            if (ptRequest->m.find("Message") != ptRequest->m.end() && !ptRequest->m["Message"]->v.empty())
                            {
                              size_t unID;
                              if (auth(strApplication, ptRequest->m["User"]->v, ptRequest->m["Password"]->v, strFunction, unID, strError, true))
                              {
                                map<string, string> label;
                                stringstream ssTime;
                                if (ptRequest->m.find("Label") != ptRequest->m.end())
                                {
                                  ptRequest->m["Label"]->flatten(label, false, false);
                                }
                                ssTime << CTime;
                                if (strFunction == "log")
                                {
                                  Bytef *pszZCompress;
                                  char *pszBZCompress;
                                  ofstream outData, outIndex;
                                  size_t unZCompress, unPosition;
                                  stringstream ssBZCompress, ssZCompress, ssIndex, ssPosition, ssSize;
                                  unsigned int unBZCompress;
                                  Json *ptIndex = new Json;
                                  ptIndex->insert("t", ssTime.str());
                                  ptIndex->m["l"] = new Json;
                                  ptIndex->m["l"]->insert(label);
                                  ssSize << ptRequest->m["Message"]->v.size();
                                  ptIndex->insert("s", ssSize.str());
                                  unBZCompress = ptRequest->m["Message"]->v.size() * 1.01 + 600;
                                  pszBZCompress = new char[unBZCompress];
                                  BZ2_bzBuffToBuffCompress(pszBZCompress, &unBZCompress, (char *)ptRequest->m["Message"]->v.c_str(), ptRequest->m["Message"]->v.size(), 9, 0, 30);
                                  ssBZCompress << unBZCompress;
                                  ptIndex->insert("b", ssBZCompress.str());
                                  unZCompress = compressBound(ptRequest->m["Message"]->v.size());
                                  pszZCompress = new Bytef[unZCompress];
                                  compress(pszZCompress, &unZCompress, (Bytef *)ptRequest->m["Message"]->v.c_str(), ptRequest->m["Message"]->v.size());
                                  ssZCompress << unZCompress;
                                  ptIndex->insert("z", ssZCompress.str());
                                  gApplication[unID]->mutexStorage.lock();
                                  ssIndex << gApplication[unID]->strIndexPrefix << ssDate.str() << gApplication[unID]->strIndexSuffix;
                                  outIndex.open(ssIndex.str().c_str(), ios::out|ios::app);
                                  if (outIndex)
                                  {
                                    stringstream ssData;
                                    ssData << gApplication[unID]->strDataPrefix << ssDate.str() << gApplication[unID]->strDataSuffix;
                                    outData.open(ssData.str().c_str(), ios::out|ios::app);
                                    if (outData)
                                    {
                                      bProcessed = true;
                                      mutexRequest.lock();
                                      gunRequests++;
                                      mutexRequest.unlock();
                                      unPosition = outData.tellp();
                                      ssPosition << unPosition;
                                      ptIndex->insert("p", ssPosition.str());
                                      outIndex << ptIndex << endl;
                                      outData.seekp(unPosition);
                                      if (unBZCompress < ptRequest->m["Message"]->v.size() && unBZCompress < unZCompress)
                                      {
                                        outData.write(pszBZCompress, unBZCompress);
                                      }
                                      else if (unZCompress < ptRequest->m["Message"]->v.size())
                                      {
                                        outData.write((char *)pszZCompress, unZCompress);
                                      }
                                      else
                                      {
                                        outData.write(ptRequest->m["Message"]->v.c_str(), ptRequest->m["Message"]->v.size());
                                      }
                                    }
                                    else
                                    {
                                      ssMessage.str("");
                                      ssMessage << "Internal Error:  request()->ofstream::open(" << errno << ") [" << ssData.str() << "]:  " << strerror(errno);
                                      ptRequest->insert("Error", ssMessage.str());
                                    }
                                    outData.close();
                                  }
                                  else
                                  {
                                    ssMessage.str("");
                                    ssMessage << "Internal Error:  request()->ofstream::open(" << errno << ") [" << ssIndex.str() << "]:  " << strerror(errno);
                                    ptRequest->insert("Error", ssMessage.str());
                                  }
                                  outIndex.close();
                                  gApplication[unID]->mutexStorage.unlock();
                                  delete[] pszBZCompress;
                                  delete[] pszZCompress;
                                  delete ptIndex;
                                }
                                else
                                {
                                  bProcessed = true;
                                  mutexRequest.lock();
                                  gunRequests++;
                                  mutexRequest.unlock();
                                }
                                mutexFeed.lock();
                                for (auto &i : gFeed)
                                {
                                  if (i.second->strApplication == strApplication)
                                  {
                                    bool bMatch = true;
                                    for (auto j = i.second->criteria.begin(); bMatch && j != i.second->criteria.end(); j++)
                                    {
                                      if (label.find(j->first) == label.end() || label[j->first] != j->second)
                                      {
                                        bMatch = false;
                                      }
                                    }
                                    if (bMatch)
                                    {
                                      Json *ptMatch = new Json;
                                      ptMatch->m["Label"] = new Json(label);
                                      ptMatch->insert("Time", ssTime.str());
                                      ptMatch->insert("Message", ptRequest->m["Message"]->v);
                                      ptMatch->json(strResponse);
                                      delete ptMatch;
                                      i.second->entry.push_back(strResponse);
                                    }
                                  }
                                }
                                mutexFeed.unlock();
                                label.clear();
                              }
                              else
                              {
                                ptRequest->insert("Error", strError);
                              }
                            }
                            else
                            {
                              ptRequest->insert("Error", "Please provide the Message.");
                            }
                          }
                          // }}}
                          // {{{ Function:  search
                          else if (strFunction == "search")
                          {
                            if (!bSearch)
                            {
                              size_t unID;
                              if (auth(strApplication, ptRequest->m["User"]->v, ptRequest->m["Password"]->v, strFunction, unID, strError))
                              {
                                if (ptRequest->m.find("Search") != ptRequest->m.end())
                                {
                                  map<string, string> s;
                                  string strStartDate, strStartTime, strEndDate, strEndTime;
                                  bProcessed = bSearch = bWrote = true;
                                  mutexRequest.lock();
                                  gunRequests++;
                                  mutexRequest.unlock();
                                  ptRequest->insert("Status", "okay");
                                  ptRequest->json(strResponse);
                                  strBuffer[1].append(strResponse);
                                  strBuffer[1].append("\n");
                                  for (auto &i : ptRequest->m["Search"]->m)
                                  {
                                    if (i.first == "Time")
                                    {
                                      if (i.second->m.find("Start") != i.second->m.end())
                                      {
                                        strStartTime = i.second->m["Start"]->v;
                                      }
                                      if (i.second->m.find("End") != i.second->m.end())
                                      {
                                        strEndTime = i.second->m["End"]->v;
                                      }
                                    }
                                    else if (!i.second->v.empty())
                                    {
                                      s[i.first] = i.second->v;
                                    }
                                  }
                                  if (!strStartTime.empty())
                                  {
                                    stringstream ssTime(strStartTime);
                                    struct tm tTime;
                                    time_t CTime;
                                    ssTime >> CTime;
                                    if (localtime_r(&CTime, &tTime) != NULL)
                                    {
                                      char szTimeStamp[9] = "\0";
                                      if (strftime(szTimeStamp, 9, "%Y%m%d", &tTime) > 0)
                                      {
                                        strStartDate = szTimeStamp;
                                      }
                                    }
                                  }
                                  if (!strEndTime.empty())
                                  {
                                    stringstream ssTime(strEndTime);
                                    struct tm tTime;
                                    time_t CTime;
                                    ssTime >> CTime;
                                    if (localtime_r(&CTime, &tTime) != NULL)
                                    {
                                      char szTimeStamp[9] = "\0";
                                      if (strftime(szTimeStamp, 9, "%Y%m%d", &tTime) > 0)
                                      {
                                        strEndDate = szTimeStamp;
                                      }
                                    }
                                  }
                                  pThreadSearch = new thread(requestSearch, unID, s, strStartDate, strStartTime, strEndDate, strEndTime, std::ref(strSearch), std::ref(bSearch));
                                  pthread_setname_np(pThreadSearch->native_handle(), "requestSearch");
                                  s.clear();
                                }
                                else
                                {
                                  ptRequest->insert("Error", "Please provide the Search.");
                                }
                              }
                              else
                              {
                                ptRequest->insert("Error", strError);
                              }
                            }
                            else
                            {
                              ptRequest->insert("Error", "Please wait for the previous search to complete before starting a new search.");
                            }
                          }
                          // }}}
                          // {{{ Function:  invalid
                          else
                          {
                            ptRequest->insert("Error", "Please provide a valid Function:  feed, log, message, search.");
                          }
                          // }}}
                        }
                        else
                        {
                          ptRequest->insert("Error", "Please provide the Function.");
                        }
                      }
                      else
                      {
                        ptRequest->insert("Error", "Please provide the Password.");
                      }
                    }
                    else
                    {
                      ptRequest->insert("Error", "Please provide the User.");
                    }
                  }
                  else
                  {
                    ptRequest->insert("Error", "Please provide the Application.");
                  }
                  if (!bWrote)
                  {
                    ptRequest->insert("Status", ((bProcessed)?"okay":"error"));
                    if (ptRequest->m.find("Label") != ptRequest->m.end())
                    {
                      delete ptRequest->m["Label"];
                      ptRequest->m.erase("Label");
                    }
                    if (ptRequest->m.find("Message") != ptRequest->m.end())
                    {
                      delete ptRequest->m["Message"];
                      ptRequest->m.erase("Message");
                    }
                    ptRequest->json(strResponse);
                    strBuffer[1].append(strResponse);
                    strBuffer[1].append("\n");
                  }
                  delete ptRequest;
                }
              }
              else
              {
                bExit = true;
                if (!bSecure && nReturn < 0)
                {
                  ssMessage.str("");
                  ssMessage << strPrefix << "->Central::utility()->fdRead(" << errno << ") error";
                  if (gFeed.find(fdSocket) != gFeed.end())
                  {
                    ssMessage << " [" << gFeed[fdSocket]->strApplication << "," << gFeed[fdSocket]->strUser << "]";
                  }
                  ssMessage << ":  " << strerror(errno);
                  gpCentral->log(ssMessage.str());
                }
                else if (bSecure && SSL_get_error(ssl, nReturn) != SSL_ERROR_ZERO_RETURN)
                {
                  ssMessage.str("");
                  ssMessage << strPrefix << "->Central::utility()->sslRead(" << SSL_get_error(ssl, nReturn) << ") error";
                  if (gFeed.find(fdSocket) != gFeed.end())
                  {
                    ssMessage << " [" << gFeed[fdSocket]->strApplication << "," << gFeed[fdSocket]->strUser << "]";
                  }
                  ssMessage << ":  " << gpCentral->utility()->sslstrerror(ssl, nReturn);
                  gpCentral->log(ssMessage.str());
                }
              }
            }
            // }}}
            // {{{ write
            if (fds[0].fd == fdSocket && (fds[0].revents & POLLOUT))
            {
              if ((!bSecure && gpCentral->utility()->fdWrite(fdSocket, strBuffer[1], nReturn)) || (bSecure && gpCentral->utility()->sslWrite(ssl, strBuffer[1], nReturn)))
              {
                if (ptFeed == NULL && !bMulti && pThreadSearch == NULL && strBuffer[1].empty())
                {
                  bExit = true;
                }
              }
              else
              {
                if (!bSecure)
                {
                  bExit = true;
                  if (nReturn < 0 || gFeed.find(fdSocket) != gFeed.end())
                  {
                    ssMessage.str("");
                    ssMessage << strPrefix << "->Central::utility()->sslWrite(" << errno << ") error";
                    if (gFeed.find(fdSocket) != gFeed.end())
                    {
                      ssMessage << " [" << gFeed[fdSocket]->strApplication << "," << gFeed[fdSocket]->strUser << "]";
                    }
                    ssMessage << ":  " << strerror(errno);
                    gpCentral->log(ssMessage.str());
                  }
                }
                else
                {
                  bExit = true;
                  ssMessage.str("");
                  ssMessage << strPrefix << "->Central::utility()->sslWrite(" << SSL_get_error(ssl, nReturn) << ") error";
                  if (gFeed.find(fdSocket) != gFeed.end())
                  {
                    ssMessage << " [" << gFeed[fdSocket]->strApplication << "," << gFeed[fdSocket]->strUser << "]";
                  }
                  ssMessage << ":  " << gpCentral->utility()->sslstrerror(ssl, nReturn);
                  gpCentral->log(ssMessage.str());
                }
                if (ptFeed != NULL)
                {
                  mutexFeed.lock();
                  if (gFeed.find(fdSocket) != gFeed.end())
                  {
                    gFeed.erase(fdSocket);
                  }
                  mutexFeed.unlock();
                  ptFeed->criteria.clear();
                  ptFeed->entry.clear();
                  delete ptFeed;
                  ptFeed = NULL;
                }
              }
            }
            // }}}
          }
          else if (nReturn < 0)
          {
            bExit = true;
            ssMessage.str("");
            ssMessage << strPrefix << "->poll(" << errno << ") error";
            if (gFeed.find(fdSocket) != gFeed.end())
            {
              ssMessage << " [" << gFeed[fdSocket]->strApplication << "," << gFeed[fdSocket]->strUser << "]";
            }
            ssMessage << ":  " << strerror(errno);
            gpCentral->log(ssMessage.str());
          }
          if (pThreadSearch != NULL && !bSearch)
          {
            pThreadSearch->join();
            delete pThreadSearch;
            pThreadSearch = NULL;
            if (!strSearch.empty())
            {
              strBuffer[1].append(strSearch);
              strSearch.clear();
            }
          }
        }
        if (ptFeed != NULL)
        {
          mutexFeed.lock();
          if (gFeed.find(fdSocket) != gFeed.end())
          {
            gFeed.erase(fdSocket);
          }
          mutexFeed.unlock();
          ptFeed->criteria.clear();
          ptFeed->entry.clear();
          delete ptFeed;
          ptFeed = NULL;
        }
        if (pThreadSearch != NULL)
        {
          bSearch = false;
          pThreadSearch->join();
          delete pThreadSearch;
          pThreadSearch = NULL;
          strSearch.clear();
        }
      }
      else
      {
        ssMessage.str("");
        ssMessage << strPrefix << "->SSL_accept(" << SSL_get_error(ssl, nReturn) << ") error:  " << gpCentral->utility()->sslstrerror(ssl, SSL_get_error(ssl, nReturn));
        gpCentral->log(ssMessage.str());
      }
    }
    else
    {
      ssMessage.str("");
      ssMessage << strPrefix << "->SSL_set_fd() error:  " << gpCentral->utility()->sslstrerror();
      gpCentral->log(ssMessage.str());
    }
    if (bSecure)
    {
      SSL_shutdown(ssl);
      SSL_free(ssl);
    }
  }
  else
  {
    ssMessage.str("");
    ssMessage << strPrefix << "->SSL_new() error:  " << gpCentral->utility()->sslstrerror();
    gpCentral->log(ssMessage.str());
  }
  close(fdSocket);
  mutexRequest.lock();
  gnRequests--;
  mutexRequest.unlock();
}
// }}}
// {{{ requestSearch()
void requestSearch(const size_t unID, map<string, string> s, const string strStartDate, const string strStartTime, const string strEndDate, const string strEndTime, string &strBuffer, bool &bSearch)
{
  list<string> dir;
  string strPrefix;
  stringstream ssMessage, ssPrefix;

  ssPrefix << "requestSearch(" << syscall(SYS_gettid) << ")";
  strPrefix = ssPrefix.str();
  gpCentral->file()->directoryList(gstrData + (string)STORAGE, dir);
  for (auto &i : dir)
  {
    stringstream ssPrefix;
    ssPrefix << unID;
    if (bSearch && i.size() == (ssPrefix.str().size() + 15) && i.substr(ssPrefix.str().size(), 1) == "-" && i.substr(0, ssPrefix.str().size() + 1) == (ssPrefix.str() + (string)"-") && i.substr(i.size() - 6, 6) == ".index")
    {
      string strDate = i.substr(ssPrefix.str().size() + 1, 8);
      if ((strStartDate.empty() || strDate >= strStartDate) && (strEndDate.empty() || strDate <= strEndDate))
      {
        ifstream inIndex;
        stringstream ssData, ssIndex;
        ssMessage.str("");
        ssMessage << strPrefix << " [" << i.substr((ssPrefix.str().size() + 1), 8) << "]:  Searching index and data files.";
        gpCentral->log(ssMessage.str());
        ssIndex << gstrData << STORAGE << "/" << i;
        ssData << gApplication[unID]->strDataPrefix << i.substr((ssPrefix.str().size() + 1), 8) << gApplication[unID]->strDataSuffix;
        inIndex.open(ssIndex.str().c_str());
        if (inIndex)
        {
          ifstream inData;
          inData.open(ssData.str().c_str(), ios::in|ios::binary);
          if (inData)
          {
            string strLine;
            while (bSearch && getline(inIndex, strLine))
            {
              bool bMatch = true;
              Json *ptJson = new Json(strLine);
              if ((!strStartTime.empty() && ptJson->m["t"]->v < strStartTime) || (!strEndTime.empty() && ptJson->m["t"]->v >= strEndTime))
              {
                bMatch = false;
              }
              if (bMatch)
              {
                for (auto i = s.begin(); bMatch && i != s.end(); i++)
                {
                  if (ptJson->m["l"]->m.find(i->first) == ptJson->m["l"]->m.end() || ptJson->m["l"]->m[i->first]->v != i->second)
                  {
                    bMatch = false;
                  }
                }
              }
              if (bMatch)
              {
                Bytef *pszZCompress;
                char *pszBuffer, *pszBZCompress;
                size_t unZCompress, unPosition, unSize;
                string strSubBuffer, strResponse;
                stringstream ssBZCompress, ssZCompress, ssData, ssPosition, ssSize;
                unsigned int unBZCompress, unTempSize;
                Json *ptData;
                ssBZCompress.str(ptJson->m["b"]->v);
                ssBZCompress >> unBZCompress;
                ssZCompress.str(ptJson->m["z"]->v);
                ssZCompress >> unZCompress;
                ssPosition.str(ptJson->m["p"]->v);
                ssPosition >> unPosition;
                ssSize.str(ptJson->m["s"]->v);
                ssSize >> unSize;
                ptData = new Json;
                ptData->insert("Time", ptJson->m["t"]->v);
                ptData->m["Label"] = new Json;
                for (auto &j : ptJson->m["l"]->m)
                {
                  ptData->m["Label"]->insert(j.first, j.second->v);
                }
                inData.seekg(unPosition);
                pszBuffer = new char[unSize];
                pszBZCompress = new char[unBZCompress];
                pszZCompress = new Bytef[unZCompress];
                if (unBZCompress < unSize && unBZCompress < unZCompress)
                {
                  inData.read(pszBZCompress, unBZCompress);
                  BZ2_bzBuffToBuffDecompress(pszBuffer, &unTempSize, pszBZCompress, unBZCompress, 0, 0);
                  unSize = unTempSize;
                }
                else if (unZCompress < unSize)
                {
                  inData.read((char *)pszZCompress, unZCompress);
                  uncompress((Bytef *)pszBuffer, &unSize, pszZCompress, unZCompress);
                }
                else
                {
                  inData.read(pszBuffer, unSize);
                }
                strSubBuffer.assign(pszBuffer, unSize);
                delete[] pszBuffer;
                delete[] pszBZCompress;
                delete[] pszZCompress;
                ptData->insert("Message", strSubBuffer);
                ptData->json(strResponse);
                delete ptData;
                strBuffer.append(strResponse);
                strBuffer.append("\n");
              }
              delete ptJson;
            }
          }
          else
          {
            ssMessage.str("");
            ssMessage << strPrefix << "->ifstream::open(" << errno << ") error [" << ssData.str() << "]:  " << strerror(errno);
            gpCentral->notify(ssMessage.str());
          }
          inData.close();
        }
        else
        {
          ssMessage.str("");
          ssMessage << strPrefix << "->ifstream::open(" << errno << ") error [" << ssIndex.str() << "]:  " << strerror(errno);
          gpCentral->notify(ssMessage.str());
        }
        inIndex.close();
      }
    }
  }
  dir.clear();
  bSearch = false;
}
// }}}
// {{{ sighandle()
void sighandle(const int nSignal)
{
  string strError, strPrefix = "sighandle()", strSignal;
  stringstream ssMessage;

  sethandles(sigdummy);
  gbShutdown = true;
  if (nSignal != SIGINT && nSignal != SIGTERM)
  {
    ssMessage.str("");
    ssMessage << strPrefix << ":  The program's signal handling caught a " << sigstring(strSignal, nSignal) << "(" << nSignal << ")!  Exiting...";
    gpCentral->notify(ssMessage.str());
  }

  exit(1);
}
// }}}
// {{{ verify()
bool verify(const string strApplication, const string strUser, const string strPassword, string &strError)
{
  bool bResult = false;
  list<string> in, out;
  string strJson;
  Json *ptJson = new Json;

  ptJson->insert("Service", "password");
  ptJson->insert("Function", "verify");
  ptJson->insert("Application", strApplication);
  ptJson->insert("User", strUser);
  ptJson->insert("Password", strPassword);
  ptJson->insert("reqApp", gstrApplication);
  in.push_back(ptJson->json(strJson));
  delete ptJson;
  if (gpCentral->junction()->request(in, out, strError))
  {
    if (!out.empty())
    {
      ptJson = new Json(out.front());
      if (ptJson->m.find("Status") != ptJson->m.end() && ptJson->m["Status"]->v == "okay")
      {
        bResult = true;
      }
      else if (ptJson->m.find("Error") != ptJson->m.end() && !ptJson->m["Error"]->v.empty())
      {
        strError = ptJson->m["Error"]->v;
      }
      else
      {
        strError = "Encountered an unknown error.";
      }
      delete ptJson;
    }
    else
    {
      strError = "Failed to receive the response.";
    }
  }
  in.clear();
  out.clear();

  return bResult;
}
// }}}

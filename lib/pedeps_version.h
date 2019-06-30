/*****************************************************************************
Copyright (C)  2019  Brecht Sanders  All Rights Reserved

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*****************************************************************************/

/**
 * @file pedeps_version.h
 * @brief pedeps header file with version information.
 * @author Brecht Sanders
 *
 * Only use this header file when version information is needed at compile
 * time. Otherwise the version functions in the libraries should be used.
 * \sa     PEDEPS_VERSION_*
 * \sa     PEDEPS_VERSION
 * \sa     PEDEPS_VERSION_STRING
 * \sa     pedeps_get_version()
 * \sa     pedeps_get_version_string()
 */

#ifndef INCLUDED_PEDEPS_VERSION_H
#define INCLUDED_PEDEPS_VERSION_H

/*! \brief version number constants
 * \sa     pedeps_get_version()
 * \sa     pedeps_get_version_string()
 * \name   PEDEPS_VERSION_*
 * \{
 */
/*! \brief major version number */
#define PEDEPS_VERSION_MAJOR 0
/*! \brief minor version number */
#define PEDEPS_VERSION_MINOR 1
/*! \brief micro version number */
#define PEDEPS_VERSION_MICRO 6
/*! @} */

/*! \brief packed version number */
#define PEDEPS_VERSION (PEDEPS_VERSION_MAJOR * 0x01000000 + PEDEPS_VERSION_MINOR * 0x00010000 + PEDEPS_VERSION_MICRO * 0x00000100)

/*! \cond PRIVATE */
#define PEDEPS_VERSION_STRINGIZE_(major, minor, micro) #major"."#minor"."#micro
#define PEDEPS_VERSION_STRINGIZE(major, minor, micro) PEDEPS_VERSION_STRINGIZE_(major, minor, micro)
/*! \endcond */

/*! \brief string with dotted version number \hideinitializer */
#define PEDEPS_VERSION_STRING PEDEPS_VERSION_STRINGIZE(PEDEPS_VERSION_MAJOR, PEDEPS_VERSION_MINOR, PEDEPS_VERSION_MICRO)

/*! \brief string with name of pedeps library */
#define PEDEPS_NAME "pedeps"

/*! \brief string with name and version of pedeps library \hideinitializer */
#define PEDEPS_FULLNAME PEDEPS_NAME " " PEDEPS_VERSION_STRING

#endif

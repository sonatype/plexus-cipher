/**
 * Copyright (c) 2008 Sonatype, Inc. All rights reserved.
 *
 * This program is licensed to you under the Apache License Version 2.0,
 * and you may not use this file except in compliance with the Apache License Version 2.0.
 * You may obtain a copy of the Apache License Version 2.0 at http://www.apache.org/licenses/LICENSE-2.0.
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the Apache License Version 2.0 is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Apache License Version 2.0 for the specific language governing permissions and limitations there under.
 */
package org.sonatype.plexus.components.cipher;

import java.security.Provider;
import java.security.Security;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.enterprise.inject.Typed;
import javax.inject.Named;

/**
 * @author Oleg Gusakov</a>
 */
@Named( "default" )
@Typed( PlexusCipher.class )
public class DefaultPlexusCipher
    implements PlexusCipher
{

    private static final Pattern ENCRYPTED_STRING_PATTERN = Pattern.compile( ".*?[^\\\\]?\\{(.*?[^\\\\])\\}.*" );

    private final PBECipher _cipher;

    // ---------------------------------------------------------------
    public DefaultPlexusCipher()
        throws PlexusCipherException
    {
        _cipher = new PBECipher();
    }

    // ---------------------------------------------------------------
    public String encrypt( final String str, final String passPhrase )
        throws PlexusCipherException
    {
        if ( str == null || str.length() < 1 )
        {
            return str;
        }

        return _cipher.encrypt64( str, passPhrase );
    }

    // ---------------------------------------------------------------
    public String encryptAndDecorate( final String str, final String passPhrase )
        throws PlexusCipherException
    {
        return decorate( encrypt( str, passPhrase ) );
    }

    // ---------------------------------------------------------------
    public String decrypt( final String str, final String passPhrase )
        throws PlexusCipherException
    {
        if ( str == null || str.length() < 1 )
        {
            return str;
        }

        return _cipher.decrypt64( str, passPhrase );
    }

    // ---------------------------------------------------------------
    public String decryptDecorated( final String str, final String passPhrase )
        throws PlexusCipherException
    {
        if ( str == null || str.length() < 1 )
        {
            return str;
        }

        if ( isEncryptedString( str ) )
        {
            return decrypt( unDecorate( str ), passPhrase );
        }

        return decrypt( str, passPhrase );
    }

    // ----------------------------------------------------------------------------
    public boolean isEncryptedString( final String str )
    {
        if ( str == null || str.length() < 1 )
        {
            return false;
        }

        Matcher matcher = ENCRYPTED_STRING_PATTERN.matcher( str );

        return matcher.matches() || matcher.find();
    }

    // ----------------------------------------------------------------------------
    // -------------------
    public String unDecorate( final String str )
        throws PlexusCipherException
    {
        Matcher matcher = ENCRYPTED_STRING_PATTERN.matcher( str );

        if ( matcher.matches() || matcher.find() )
        {
            return matcher.group( 1 );
        }
        else
        {
            throw new PlexusCipherException( "default.plexus.cipher.badEncryptedPassword" );
        }
    }

    // ----------------------------------------------------------------------------
    // -------------------
    public String decorate( final String str )
    {
        return ENCRYPTED_STRING_DECORATION_START + ( str == null ? "" : str ) + ENCRYPTED_STRING_DECORATION_STOP;
    }

    // ---------------------------------------------------------------
    // ---------------------------------------------------------------
    // ***************************************************************
    /**
     * Exploratory part. This method returns all available services types
     */
    public static String[] getServiceTypes()
    {
        Set result = new HashSet();

        // All all providers
        Provider[] providers = Security.getProviders();
        for ( int i = 0; i < providers.length; i++ )
        {
            // Get services provided by each provider
            Set keys = providers[i].keySet();
            for ( Iterator it = keys.iterator(); it.hasNext(); )
            {
                String key = (String) it.next();
                key = key.split( " " )[0];

                if ( key.startsWith( "Alg.Alias." ) )
                {
                    // Strip the alias
                    key = key.substring( 10 );
                }
                int ix = key.indexOf( '.' );
                result.add( key.substring( 0, ix ) );
            }
        }
        return (String[]) result.toArray( new String[result.size()] );
    }

    /**
     * This method returns the available implementations for a service type
     */
    public static String[] getCryptoImpls( final String serviceType )
    {
        Set result = new HashSet();

        // All all providers
        Provider[] providers = Security.getProviders();
        for ( int i = 0; i < providers.length; i++ )
        {
            // Get services provided by each provider
            Set keys = providers[i].keySet();
            for ( Iterator it = keys.iterator(); it.hasNext(); )
            {
                String key = (String) it.next();
                key = key.split( " " )[0];

                if ( key.startsWith( serviceType + "." ) )
                {
                    result.add( key.substring( serviceType.length() + 1 ) );
                }
                else if ( key.startsWith( "Alg.Alias." + serviceType + "." ) )
                {
                    // This is an alias
                    result.add( key.substring( serviceType.length() + 11 ) );
                }
            }
        }
        return (String[]) result.toArray( new String[result.size()] );
    }

    // ---------------------------------------------------------------
    public static void main( final String[] args )
    {
        // Security.addProvider( new BouncyCastleProvider() );

        String[] serviceTypes = getServiceTypes();
        if ( serviceTypes != null )
        {
            for ( int i = 0; i < serviceTypes.length; i++ )
            {
                String serviceType = serviceTypes[i];
                String[] serviceProviders = getCryptoImpls( serviceType );
                if ( serviceProviders != null )
                {
                    System.out.println( serviceType + ": provider list" );
                    for ( int j = 0; j < serviceProviders.length; j++ )
                    {
                        String provider = serviceProviders[j];
                        System.out.println( "        " + provider );
                    }
                }
                else
                {
                    System.out.println( serviceType + ": does not have any providers in this environment" );
                }
            }
        }
    }
    // ---------------------------------------------------------------
    // ---------------------------------------------------------------
}

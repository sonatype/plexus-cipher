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

import org.codehaus.plexus.logging.AbstractLogEnabled;

/**
 * @plexus.component
 * @author Oleg Gusakov</a>
 */
public class DefaultPlexusCipher
extends AbstractLogEnabled
implements PlexusCipher
{
    private PBECipher _cipher;
    
    // ---------------------------------------------------------------
    public DefaultPlexusCipher()
    throws PlexusCipherException
    {
        _cipher = new PBECipher();
    }
    // ---------------------------------------------------------------
    public String encrypt( String str, String passPhrase )
    throws PlexusCipherException
    {
        if ( str == null || str.length() < 1 )
            return str;

        return _cipher.encrypt64( str, passPhrase );
    }

    // ---------------------------------------------------------------
    public String encryptAndDecorate( String str, String passPhrase )
        throws PlexusCipherException
    {
        return decorate( encrypt( str, passPhrase ) );
    }

    // ---------------------------------------------------------------
    public String decrypt( String str, String passPhrase )
        throws PlexusCipherException
    {
        if ( str == null || str.length() < 1 )
            return str;

        return _cipher.decrypt64( str, passPhrase );
    }

    // ---------------------------------------------------------------
    public String decryptDecorated( String str, String passPhrase )
        throws PlexusCipherException
    {
        if ( str == null || str.length() < 1 )
            return str;

        if ( isEncryptedString( str ) )
            return decrypt( unDecorate( str ), passPhrase );

        return decrypt( str, passPhrase );
    }

    // ----------------------------------------------------------------------------
    public boolean isEncryptedString( String str )
    {
        if ( str == null || str.length() < 1 )
            return false;

        int start = str.indexOf( ENCRYPTED_STRING_DECORATION_START );
        int stop = str.indexOf( ENCRYPTED_STRING_DECORATION_STOP );
        if ( start != -1 && stop != -1 && stop > start + 1 )
            return true;
        
        return false;
    }

    // ----------------------------------------------------------------------------
    // -------------------
    public String unDecorate( String str )
        throws PlexusCipherException
    {
        if ( !isEncryptedString( str ) )
            throw new PlexusCipherException( "default.plexus.cipher.badEncryptedPassword" );

        int start = str.indexOf( ENCRYPTED_STRING_DECORATION_START );
        int stop = str.indexOf( ENCRYPTED_STRING_DECORATION_STOP );
        return str.substring( start + 1, stop );
    }

    // ----------------------------------------------------------------------------
    // -------------------
    public String decorate( String str )
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
    public static String[] getCryptoImpls( String serviceType )
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
    public static void main( String[] args )
    {
//        Security.addProvider( new BouncyCastleProvider() );   

        String[] serviceTypes = getServiceTypes();
        if ( serviceTypes != null )
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
    //---------------------------------------------------------------
    //---------------------------------------------------------------
}

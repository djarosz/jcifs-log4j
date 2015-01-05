/* jcifs smb client library in Java
 * Copyright (C) 2000  "Michael B. Allen" <jcifs at samba dot org>
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

package jcifs.smb;

import java.util.Date;
import java.io.UnsupportedEncodingException;
import jcifs.util.Hexdump;

class SmbComNegotiateResponse extends ServerMessageBlock {

    int dialectIndex;
    SmbTransport.ServerData server;

    SmbComNegotiateResponse( SmbTransport.ServerData server ) {
        this.server = server;
    }

    int writeParameterWordsWireFormat( byte[] dst, int dstIndex ) {
        return 0;
    }
    int writeBytesWireFormat( byte[] dst, int dstIndex ) {
        return 0;
    }
    int readParameterWordsWireFormat( byte[] buffer,
                                    int bufferIndex ) {
        int start = bufferIndex;

        dialectIndex         = readInt2( buffer, bufferIndex ); bufferIndex += 2;
        if( dialectIndex > 10 ) {
            return bufferIndex - start;
        }
        server.setSecurityMode(buffer[bufferIndex++] & 0xFF);
        server.setSecurity(server.getSecurityMode() & 0x01);
        server.setEncryptedPasswords(( server.getSecurityMode() & 0x02 ) == 0x02);
        server.setSignaturesEnabled(( server.getSecurityMode() & 0x04 ) == 0x04);
        server.setSignaturesRequired(( server.getSecurityMode() & 0x08 ) == 0x08);
        server.setMaxMpxCount(readInt2( buffer, bufferIndex )); bufferIndex += 2;
        server.setMaxNumberVcs(readInt2( buffer, bufferIndex )); bufferIndex += 2;
        server.setMaxBufferSize(readInt4( buffer, bufferIndex )); bufferIndex += 4;
        server.setMaxRawSize(readInt4( buffer, bufferIndex )); bufferIndex += 4;
        server.setSessionKey(readInt4( buffer, bufferIndex )); bufferIndex += 4;
        server.setCapabilities(readInt4( buffer, bufferIndex )); bufferIndex += 4;
        server.setServerTime(readTime( buffer, bufferIndex )); bufferIndex += 8;
        server.setServerTimeZone(readInt2( buffer, bufferIndex )); bufferIndex += 2;
        server.setEncryptionKeyLength(buffer[bufferIndex++] & 0xFF);

        return bufferIndex - start;
    }
    int readBytesWireFormat( byte[] buffer,
                                    int bufferIndex ) {
        int start = bufferIndex;

        server.setEncryptionKey(new byte[server.getEncryptionKeyLength()]);
        System.arraycopy( buffer, bufferIndex,
                server.getEncryptionKey(), 0, server.getEncryptionKeyLength() );
        bufferIndex += server.getEncryptionKeyLength();
        if( byteCount > server.getEncryptionKeyLength() ) {
            int len = 0;
            try {
                if(( flags2 & FLAGS2_UNICODE ) == FLAGS2_UNICODE ) {
                    while( buffer[bufferIndex + len] != (byte)0x00 ||
                                    buffer[bufferIndex + len + 1] != (byte)0x00 ) {
                        len += 2;
                        if( len > 256 ) {
                            throw new RuntimeException( "zero termination not found" );
                        }
                    }
                    server.setOemDomainName(new String( buffer, bufferIndex,
                            len, "UnicodeLittleUnmarked" ));
                } else {
                    while( buffer[bufferIndex + len] != (byte)0x00 ) {
                        len++;
                        if( len > 256 ) {
                            throw new RuntimeException( "zero termination not found" );
                        }
                    }
                    server.setOemDomainName(new String( buffer, bufferIndex,
                            len, ServerMessageBlock.OEM_ENCODING ));
                }
            } catch( UnsupportedEncodingException uee ) {
                if( log.level > 1 )
                    uee.printStackTrace( log );
            }
            bufferIndex += len;
        } else {
            server.setOemDomainName(new String());
        }

        return bufferIndex - start;
    }
    public String toString() {
        return new String( "SmbComNegotiateResponse[" +
            super.toString() +
            ",wordCount="           + wordCount +
            ",dialectIndex="        + dialectIndex +
            ",securityMode=0x"      + Hexdump.toHexString( server.getSecurityMode(), 1 ) +
            ",security="            + ( server.getSecurity() == SECURITY_SHARE ? "share" : "user" ) +
            ",encryptedPasswords="  + server.isEncryptedPasswords() +
            ",maxMpxCount="         + server.getMaxMpxCount() +
            ",maxNumberVcs="        + server.getMaxNumberVcs() +
            ",maxBufferSize="       + server.getMaxBufferSize() +
            ",maxRawSize="          + server.getMaxRawSize() +
            ",sessionKey=0x"        + Hexdump.toHexString( server.getSessionKey(), 8 ) +
            ",capabilities=0x"      + Hexdump.toHexString( server.getCapabilities(), 8 ) +
            ",serverTime="          + new Date( server.getServerTime() ) +
            ",serverTimeZone="      + server.getServerTimeZone() +
            ",encryptionKeyLength=" + server.getEncryptionKeyLength() +
            ",byteCount="           + byteCount +
            ",encryptionKey=0x"     + Hexdump.toHexString( server.getEncryptionKey(),
                                                0,
                                                server.getEncryptionKeyLength() * 2 ) +
            ",oemDomainName="       + server.getOemDomainName() + "]" );
    }
}


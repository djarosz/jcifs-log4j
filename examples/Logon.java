import jcifs.*;
import jcifs.smb.*;

public class Logon {

    /* java Logon 192.168.1.15 "dom;user:pass"
     */

    public static void main( String argv[] ){
        UniAddress dc = UniAddress.getByName( "spawalnia" );
        NtlmPasswordAuthentication auth = new NtlmPasswordAuthentication( "javart4" );
        SmbSession.logon( dc, auth );
    }
}


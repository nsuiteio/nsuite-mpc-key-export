export namespace main {
	
	export class GeneratedKeyPair {
	    qrImage: string;
	    fingerprint: string;
	    publicKeyHex: string;
	
	    static createFrom(source: any = {}) {
	        return new GeneratedKeyPair(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.qrImage = source["qrImage"];
	        this.fingerprint = source["fingerprint"];
	        this.publicKeyHex = source["publicKeyHex"];
	    }
	}
	export class KeyPairInfo {
	    fingerprint: string;
	    publicKeyHex: string;
	
	    static createFrom(source: any = {}) {
	        return new KeyPairInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.fingerprint = source["fingerprint"];
	        this.publicKeyHex = source["publicKeyHex"];
	    }
	}

}


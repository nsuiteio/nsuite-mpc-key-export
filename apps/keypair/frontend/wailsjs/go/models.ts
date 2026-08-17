export namespace main {
	
	export class GeneratedKeyPair {
	    qrImage: string;
	    fingerprint: string;
	    publicKeyHex: string;
	    filePath: string;
	
	    static createFrom(source: any = {}) {
	        return new GeneratedKeyPair(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.qrImage = source["qrImage"];
	        this.fingerprint = source["fingerprint"];
	        this.publicKeyHex = source["publicKeyHex"];
	        this.filePath = source["filePath"];
	    }
	}

}


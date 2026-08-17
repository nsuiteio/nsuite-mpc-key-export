export namespace main {
	
	export class KeyPairInfo {
	    fingerprint: string;
	    publicKeyHex: string;
	    filePath: string;
	
	    static createFrom(source: any = {}) {
	        return new KeyPairInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.fingerprint = source["fingerprint"];
	        this.publicKeyHex = source["publicKeyHex"];
	        this.filePath = source["filePath"];
	    }
	}

}


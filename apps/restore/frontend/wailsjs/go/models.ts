export namespace main {
	
	export class AddressEntry {
	    index: number;
	    address: string;
	
	    static createFrom(source: any = {}) {
	        return new AddressEntry(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.index = source["index"];
	        this.address = source["address"];
	    }
	}
	export class KeyPairInfo {
	    fingerprint: string;
	    filePath: string;
	
	    static createFrom(source: any = {}) {
	        return new KeyPairInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.fingerprint = source["fingerprint"];
	        this.filePath = source["filePath"];
	    }
	}

}


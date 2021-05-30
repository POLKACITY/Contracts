// SPDX-License-Identifier: MIT

pragma solidity 0.8.2;

interface IERC721 {
    function getTokenDetails(uint256 index) external view returns (uint32 aType, uint32 customDetails, uint32 lastTx, uint32 lastPayment, uint256 initialvalue, string memory coin);
    function balanceOf(address owner) external view returns (uint256 balance);
    function tokenOfOwnerByIndex(address owner, uint256 index) external view returns (uint256 tokenId);
}

contract Ownable {

    address private owner;
    
    event OwnerSet(address indexed oldOwner, address indexed newOwner);
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Caller is not owner");
        _;
    }

    constructor() {
        owner = msg.sender; // 'msg.sender' is sender of current call, contract deployer for a constructor
        emit OwnerSet(address(0), owner);
    }


    function changeOwner(address newOwner) public onlyOwner {
        emit OwnerSet(owner, newOwner);
        owner = newOwner;
    }

    function getOwner() external view returns (address) {
        return owner;
    }
}

contract MarketFees is Ownable {
    IERC721 nftContract;
    struct FeeFactor {
        uint256 mulFactor;
        uint256 divFactor;
    }
    mapping (uint32 => bool) public zerofeeAssets;
    mapping (address => FeeFactor) public tokenFee;
    
    uint256 public ethFeeFactor;

    mapping (address => bool) public managers;
    uint8 private managersCount;
    uint16 public taskIndex;

    modifier isManager() {
        require(managers[msg.sender] == true, "Not manager");
        _;
    }

    constructor() {
        nftContract = IERC721(0xB20217bf3d89667Fa15907971866acD6CcD570C8);
        zerofeeAssets[24] = true;
    }
    
    
    function calcByToken(address _seller, address _token, uint256 _amount) public view returns (uint256 fee) {
        if (tokenFee[_token].mulFactor == 0) {
            return (0);
        } else {
            if (checkZeroFeeAsset(_seller)) {
                return (0);
            } else {
                return ((_amount*tokenFee[_token].mulFactor)/tokenFee[_token].divFactor);
            }
        }
        
    }
    
    function checkZeroFeeAsset(address _seller) private view returns (bool free) {
        uint256 assetCount = nftContract.balanceOf(_seller);
        bool freeTrade;
  
        for (uint i=0; i<assetCount; i++) {
            (uint32 assetType,,,,,) = (nftContract.getTokenDetails(nftContract.tokenOfOwnerByIndex(_seller, i)));
            if (zerofeeAssets[assetType] == true) {
                freeTrade = true;
                break;
            }
        }
        return (freeTrade);
    }
    
    function calcByEth(address _seller, uint256 _amount) public view returns (uint256 fee) {
        if (ethFeeFactor == 0) {
            return (0);
        } else {
            if (checkZeroFeeAsset(_seller)) {
                return (0);
            } else {
                return ((_amount*ethFeeFactor)/1000);
            }
        }
    }
    
    function setTokenFee(address _token, uint256 _mulFactor, uint256 _divFactor, bytes memory _sig) public isManager {
        uint8 mId = 1;
        bytes32 taskHash = keccak256(abi.encode(_token, _mulFactor, _divFactor, taskIndex, mId));
        require(verifyApproval(taskHash, _sig) == true, "Invalid 2nd approval");
        tokenFee[_token].mulFactor = _mulFactor;
        tokenFee[_token].divFactor = _divFactor;
    }
    
    function setEthFee(uint256 _fee, bytes memory _sig) public isManager {
        uint8 mId = 2;
        bytes32 taskHash = keccak256(abi.encode(_fee, taskIndex, mId));
        require(verifyApproval(taskHash, _sig) == true, "Invalid 2nd approval");
        ethFeeFactor = _fee;
    }
    
    function splitSignature(bytes memory _sig) internal pure returns (uint8, bytes32, bytes32)  {
        require(_sig.length == 65);
        bytes32 r;
        bytes32 s;
        uint8 v;
    
        assembly {
          r := mload(add(_sig, 32))
          s := mload(add(_sig, 64))
          v := byte(0, mload(add(_sig, 96)))
        }
        return (v, r, s);
    }

    function recoverSigner(bytes32 message, bytes memory _sig) internal pure returns (address)  {
        uint8 v;
        bytes32 r;
        bytes32 s;
        (v, r, s) = splitSignature(_sig);
        return ecrecover(message, v, r, s);
    }
  
    function verifyApproval(bytes32 _taskHash, bytes memory _sig) private returns(bool approved) {
        address signer = recoverSigner(_taskHash, _sig);
        if (managers[signer] == true){
            taskIndex +=1;
            return(true);
        } else {
            return(false);
        }
    }
    
}

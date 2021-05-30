// SPDX-License-Identifier: MIT

pragma solidity 0.8.2;

interface ItokenRecipient { 
    function receiveApproval(address _from, uint256 _value, address _token, bytes calldata _extraData) external returns (bool); 
}

interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address recipient, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
}

interface IERC20Metadata is IERC20 {
    function name() external view returns (string memory);
    function symbol() external view returns (string memory);
    function decimals() external view returns (uint8);
}

library Address {

    function isContract(address account) internal view returns (bool) {
        // This method relies on extcodesize, which returns 0 for contracts in
        // construction, since the code is only stored at the end of the
        // constructor execution.

        uint256 size;
        // solhint-disable-next-line no-inline-assembly
        assembly { size := extcodesize(account) }
        return size > 0;
    }


    function sendValue(address payable recipient, uint256 amount) internal {
        require(address(this).balance >= amount, "Address: insufficient balance");

        // solhint-disable-next-line avoid-low-level-calls, avoid-call-value
        (bool success, ) = recipient.call{ value: amount }("");
        require(success, "Address: unable to send value, recipient may have reverted");
    }

   
    function functionCall(address target, bytes memory data) internal returns (bytes memory) {
      return functionCall(target, data, "Address: low-level call failed");
    }

    
    function functionCall(address target, bytes memory data, string memory errorMessage) internal returns (bytes memory) {
        return functionCallWithValue(target, data, 0, errorMessage);
    }

    
    function functionCallWithValue(address target, bytes memory data, uint256 value) internal returns (bytes memory) {
        return functionCallWithValue(target, data, value, "Address: low-level call with value failed");
    }

    
    function functionCallWithValue(address target, bytes memory data, uint256 value, string memory errorMessage) internal returns (bytes memory) {
        require(address(this).balance >= value, "Address: insufficient balance for call");
        require(isContract(target), "Address: call to non-contract");

        // solhint-disable-next-line avoid-low-level-calls
        (bool success, bytes memory returndata) = target.call{ value: value }(data);
        return _verifyCallResult(success, returndata, errorMessage);
    }

   
    function functionStaticCall(address target, bytes memory data) internal view returns (bytes memory) {
        return functionStaticCall(target, data, "Address: low-level static call failed");
    }

    
    function functionStaticCall(address target, bytes memory data, string memory errorMessage) internal view returns (bytes memory) {
        require(isContract(target), "Address: static call to non-contract");

        // solhint-disable-next-line avoid-low-level-calls
        (bool success, bytes memory returndata) = target.staticcall(data);
        return _verifyCallResult(success, returndata, errorMessage);
    }

   
    function functionDelegateCall(address target, bytes memory data) internal returns (bytes memory) {
        return functionDelegateCall(target, data, "Address: low-level delegate call failed");
    }

  
    function functionDelegateCall(address target, bytes memory data, string memory errorMessage) internal returns (bytes memory) {
        require(isContract(target), "Address: delegate call to non-contract");

        // solhint-disable-next-line avoid-low-level-calls
        (bool success, bytes memory returndata) = target.delegatecall(data);
        return _verifyCallResult(success, returndata, errorMessage);
    }

    function _verifyCallResult(bool success, bytes memory returndata, string memory errorMessage) private pure returns(bytes memory) {
        if (success) {
            return returndata;
        } else {
            // Look for revert reason and bubble it up if present
            if (returndata.length > 0) {
                // The easiest way to bubble the revert reason is using memory via assembly

                // solhint-disable-next-line no-inline-assembly
                assembly {
                    let returndata_size := mload(returndata)
                    revert(add(32, returndata), returndata_size)
                }
            } else {
                revert(errorMessage);
            }
        }
    }
}

abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes calldata) {
        this; // silence state mutability warning without generating bytecode - see https://github.com/ethereum/solidity/issues/2691
        return msg.data;
    }
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

contract POLCToken is Ownable, Context, IERC20, IERC20Metadata {
    mapping (address => uint256) private _balances;

    mapping (address => mapping (address => uint256)) private _allowances;

    uint256 private _totalSupply;

    string private _name;
    string private _symbol;

    struct TimeLock {
        uint256 totalAmount;
        uint256 lockedBalance;
        uint128 baseDate;
        uint64 step;
        uint64 tokensStep;
    }
    mapping (address => TimeLock) public timeLocks; 

    // Prevent Bots - If true, limits transactions to 1 transfer per block (whitelisted can execute multiple transactions)
    bool public limitTransactions;
    mapping (address => bool) public contractsWhiteList;
    mapping (address => uint) public lastTXBlock;
    
    mapping (address => bool) public managers;
    uint8 private managersCount;
    uint16 public taskIndex;

// token sale

    // Wallet for the tokens to be sold, and receive ETH
    address payable public salesWallet;
    uint256 public soldOnCSale;
    uint256 public constant CROWDSALE_START = 1613926800;
    uint256 public constant CROWDSALE_END = 1614556740;
    uint256 public constant CSALE_WEI_FACTOR = 15000;
    uint256 public constant CSALE_HARDCAP = 7500000 ether;

    modifier isManager() {
        require(managers[msg.sender] == true, "Not manager");
        _;
    }

    constructor() {
        _totalSupply = 250000000 ether;
        _name = "Polka City";
        _symbol = "POLC";
        // Base date to calculate team, marketing and platform tokens lock
        uint256 lockStartDate = 1613494800;
        
        // Team wallet - 10000000 tokens
        // 0 tokens free, 10000000 tokens locked - progressive release of 5% every 30 days (after 180 days of waiting period)
        address team = 0x4ef5B3d10fD217AC7ddE4DDee5bF319c5c356723;
        _balances[team] = 10000000 ether;
        timeLocks[team] = TimeLock(10000000 ether, 10000000 ether, uint128(lockStartDate + (180 days)), 30 days, 500000);
        emit Transfer(address(0x0), team,_balances[team]);

        // Marketing wallet - 5000000 tokens
        // 1000000 tokens free, 4000000 tokens locked - progressive release of 5% every 30 days
        address marketingWallet = 0x056F878d4Ac07E66C9a46a8db4918E827c6fD71c;
        _balances[marketingWallet] = 5000000 ether;
        timeLocks[marketingWallet] = TimeLock(4000000 ether, 4000000 ether, uint128(lockStartDate), 30 days, 200000);
        emit Transfer(address(0x0), marketingWallet,_balances[marketingWallet]);
        
        // Private sale wallet - 2500000 tokens
        address privateWallet = 0xED854fCF86efD8473F174d6dE60c8A5EBDdCc37A;
        _balances[privateWallet] = 2500000 ether;
        emit Transfer(address(0x0), privateWallet, _balances[privateWallet]);
        
        // Sales wallet, holds Pre-Sale balance - 7500000 tokens
        salesWallet = payable(0x4bb74E94c1EB133a6868C53aA4f6BD437F99c347);
        _balances[salesWallet] = 7500000 ether;
        emit Transfer(address(0x0), salesWallet, _balances[salesWallet]);
        
        // Exchanges - 25000000 tokens
        address exchanges = 0xE50d4358425a93702988eCd8B66c2EAD8b41CE5d;  
        _balances[exchanges] = 25000000 ether;
        emit Transfer(address(0x0), exchanges, _balances[exchanges]);
        
        // Platform wallet - 200000000 tokens
        // 50000000 tokens free, 150000000 tokens locked - progressive release of 25000000 every 90 days
        address platformWallet = 0xAD334543437EF71642Ee59285bAf2F4DAcBA613F;
        _balances[platformWallet] = 200000000 ether;
        timeLocks[platformWallet] = TimeLock(150000000 ether, 150000000 ether, uint128(lockStartDate), 90 days, 25000000);
        emit Transfer(address(0x0), platformWallet, _balances[platformWallet]);

    }

    function checkTransferLimit(address _sender) internal returns (bool) {
        if (limitTransactions == true && contractsWhiteList[_sender] != true) {
            if (lastTXBlock[_sender] == block.number) {
                return false;
            } else {
                lastTXBlock[_sender] = block.number;
                return true;
            }
        } else {
            return true;
        }
    }

    function name() public view virtual override returns (string memory) {
        return _name;
    }

    function symbol() public view virtual override returns (string memory) {
        return _symbol;
    }

    function decimals() public view virtual override returns (uint8) {
        return 18;
    }

    function totalSupply() public view virtual override returns (uint256) {
        return _totalSupply;
    }

    function balanceOf(address account) public view virtual override returns (uint256) {
        return _balances[account];
    }

    function transfer(address recipient, uint256 amount) public virtual override returns (bool) {
        require(checkTransferLimit(_msgSender()), "Transfers are limited to 1 per block");
        require(amount <= (_balances[_msgSender()] - timeLocks[_msgSender()].lockedBalance));
        _transfer(_msgSender(), recipient, amount);
        return true;
    }

    function allowance(address owner, address spender) public view virtual override returns (uint256) {
        return _allowances[owner][spender];
    }

    function approve(address spender, uint256 amount) public virtual override returns (bool) {
        _approve(_msgSender(), spender, amount);
        return true;
    }

    function transferFrom(address sender, address recipient, uint256 amount) public virtual override returns (bool) {
        require(checkTransferLimit(sender), "Transfers are limited to 1 per block");
        require(amount <= (_balances[sender] - timeLocks[sender].lockedBalance));
        _transfer(sender, recipient, amount);

        uint256 currentAllowance = _allowances[sender][_msgSender()];
        require(currentAllowance >= amount, "ERC20: transfer amount exceeds allowance");
        unchecked {
            _approve(sender, _msgSender(), currentAllowance - amount);
        }

        return true;
    }

    function increaseAllowance(address spender, uint256 addedValue) public virtual returns (bool) {
        _approve(_msgSender(), spender, _allowances[_msgSender()][spender] + addedValue);
        return true;
    }

    function decreaseAllowance(address spender, uint256 subtractedValue) public virtual returns (bool) {
        uint256 currentAllowance = _allowances[_msgSender()][spender];
        require(currentAllowance >= subtractedValue, "ERC20: decreased allowance below zero");
        unchecked {
            _approve(_msgSender(), spender, currentAllowance - subtractedValue);
        }

        return true;
    }

    function burn(uint256 _value) public returns (bool) {
        _burn(_msgSender(), _value);
        return true;
    }

    function approveAndCall(address _spender, uint256 _value, bytes memory _extraData) public returns (bool) {
        _allowances[_msgSender()][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        ItokenRecipient recipient = ItokenRecipient(_spender);
        require(recipient.receiveApproval(msg.sender, _value, address(this), _extraData));
        return true;
    }

    function releaseTokens(address _account) public {
        uint256 timeDiff = block.timestamp - uint256(timeLocks[_account].baseDate);
        require(timeDiff > uint256(timeLocks[_account].step), "Unlock point not reached yet");
        uint256 steps = (timeDiff / uint256(timeLocks[_account].step));
        uint256 unlockableAmount = ((uint256(timeLocks[_account].tokensStep) * 1 ether) * steps);
        if (unlockableAmount >=  timeLocks[_account].totalAmount) {
            timeLocks[_account].lockedBalance = 0;
        } else {
            timeLocks[_account].lockedBalance = timeLocks[_account].totalAmount - unlockableAmount;
        }
    }

    function enableTXLimit(bytes memory _sig) public isManager {
        uint8 mId = 1;
        bytes32 taskHash = keccak256(abi.encode(taskIndex, mId));
        require(verifyApproval(taskHash, _sig) == true, "Invalid 2nd approval");
        limitTransactions = true;
    }
    
    function disableTXLimit(bytes memory _sig) public isManager {
        uint8 mId = 2;
        bytes32 taskHash = keccak256(abi.encode(taskIndex, mId));
        require(verifyApproval(taskHash, _sig) == true, "Invalid 2nd approval");
        limitTransactions = false;
    }
    
    function includeWhiteList(address _contractAddress, bytes memory _sig) public isManager {
        uint8 mId = 3;
        bytes32 taskHash = keccak256(abi.encode(_contractAddress, taskIndex, mId));
        require(verifyApproval(taskHash, _sig) == true, "Invalid 2nd approval");
        contractsWhiteList[_contractAddress] = true;
    }
    
    function removeWhiteList(address _contractAddress, bytes memory _sig) public isManager {
        uint8 mId = 4;
        bytes32 taskHash = keccak256(abi.encode(_contractAddress, taskIndex, mId));
        require(verifyApproval(taskHash, _sig) == true, "Invalid 2nd approval");
        contractsWhiteList[_contractAddress] = false;
    }
    
    function getLockedBalance(address _wallet) public view returns (uint256 lockedBalance) {
        return timeLocks[_wallet].lockedBalance;
    }

    function buy() public payable {
        require((block.timestamp > CROWDSALE_START) && (block.timestamp < CROWDSALE_END), "Contract is not selling tokens");
        uint weiValue = msg.value;
        require(weiValue >= (5 * (10 ** 16)), "Minimum amount is 0.05 eth");
        require(weiValue <= (20 ether), "Maximum amount is 20 eth");
        uint amount = CSALE_WEI_FACTOR * weiValue;
        require((soldOnCSale) <= (CSALE_HARDCAP), "That quantity is not available");
        soldOnCSale += amount;
        _transfer(salesWallet, _msgSender(), amount);
        Address.sendValue(payable(salesWallet), weiValue);
    }
    
    function burnUnsold(bytes memory _sig) public isManager {
        require(block.timestamp > CROWDSALE_END);
        uint8 mId = 5;
        bytes32 taskHash = keccak256(abi.encode(taskIndex, mId));
        require(verifyApproval(taskHash, _sig) == true, "Invalid 2nd approval");
        uint currentBalance = _balances[salesWallet];
        _burn(salesWallet, currentBalance);
    }

    function _transfer(address sender, address recipient, uint256 amount) internal virtual {
        require(sender != address(0), "ERC20: transfer from the zero address");
        require(recipient != address(0), "ERC20: transfer to the zero address");

        _beforeTokenTransfer(sender, recipient, amount);

        uint256 senderBalance = _balances[sender];
        require(senderBalance >= amount, "ERC20: transfer amount exceeds balance");
        unchecked {
            _balances[sender] = senderBalance - amount;
        }
        _balances[recipient] += amount;

        emit Transfer(sender, recipient, amount);
    }

    function _mint(address account, uint256 amount) internal virtual {
        require(account != address(0), "ERC20: mint to the zero address");

        _beforeTokenTransfer(address(0), account, amount);

        _totalSupply += amount;
        _balances[account] += amount;
        emit Transfer(address(0), account, amount);
    }

    function _burn(address account, uint256 amount) internal virtual {
        require(account != address(0), "ERC20: burn from the zero address");

        _beforeTokenTransfer(account, address(0), amount);

        uint256 accountBalance = _balances[account];
        require(accountBalance >= amount, "ERC20: burn amount exceeds balance");
        unchecked {
            _balances[account] = accountBalance - amount;
        }
        _totalSupply -= amount;

        emit Transfer(account, address(0), amount);
    }

    function _approve(address owner, address spender, uint256 amount) internal virtual {
        require(owner != address(0), "ERC20: approve from the zero address");
        require(spender != address(0), "ERC20: approve to the zero address");

        _allowances[owner][spender] = amount;
        emit Approval(owner, spender, amount);
    }

    function _beforeTokenTransfer(address from, address to, uint256 amount) internal virtual { }

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



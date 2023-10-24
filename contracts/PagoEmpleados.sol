// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Counters.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";

/**
 * @title PagoEmpleados
 * @dev Contrato para gestionar el pago de salarios a empleados con diferentes roles.
 */
contract PagoEmpleados is AccessControl, ReentrancyGuard {
    using SafeMath for uint256;
    using Counters for Counters.Counter;

    bytes32 public constant MODERADOR_ROLE = keccak256("MODERADOR");
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN");
    bytes32 public constant OBSERVER_ROLE = keccak256("OBSERVER");
    bytes32 public constant ACCOUNTANT_ROLE = keccak256("ACCOUNTANT");

    address private goon;
    Counters.Counter private paymentId;

    struct Payment {
        address recipient;
        uint256 amount;
        uint256 timestamp;
    }

    struct Employee {
        uint256 salary;
        uint256 lastPayment;
        bool authorizedToClaim;
        bool active;
    }

    mapping(address => Employee) public employees;
    mapping(uint256 => Payment) public payments;
    mapping(address => uint256) public reservedFunds; // Fondos reservados para cada empleado

    /**
     * @notice   EVENTOS
     */

    event EmployeeAdded(address indexed employee, uint256 salary);
    event EmployeeWithRoleAdded(
        address indexed employee,
        uint256 salary,
        bytes32 role
    );
    event EmployeeRemoved(address indexed employee);
    event EmployeeActive(address _wallet, bool _active);
    event SalaryClaimed(address indexed employee, uint256 amount);
    event SalaryChanged(
        address indexed employee,
        uint256 oldSalary,
        uint256 newSalary
    );
    event ObserverAdded(address indexed observer);
    event ObserverRemoved(address indexed observer);
    event AuthorizedToClaim(address indexed observer, address indexed employee);
    event RevokedAuthorizationToClaim(
        address indexed observer,
        address indexed employee
    );
    event Deposited(address indexed sender, uint256 amount);
    event FundsReserved(address indexed employee, uint256 amount);
    event FundsAdjusted(address indexed employee, int256 adjustmentAmount);

    /**
     * @notice   MODIFIERS
     */

    modifier onlyGoon() {
        require(msg.sender == goon, "Only the Goon can call this function.");
        _;
    }

    modifier onlyGoonOrAccountant() {
        require(
            msg.sender == goon || hasRole(ACCOUNTANT_ROLE, msg.sender),
            "Only the Goon or Accountant can call this function."
        );
        _;
    }

    modifier onlyObserver() {
        require(
            hasRole(OBSERVER_ROLE, msg.sender),
            "Only an Observer can call this function."
        );
        _;
    }

    modifier isActive(address _employee) {
        require(employees[_employee].active, "This address is not active.");
        _;
    }

    constructor() {
        goon = msg.sender;
        grantRole(DEFAULT_ADMIN_ROLE, goon);
    }

    /**
     * @notice   FUNCTIONS
     */

    /**
     * @notice Agrega un empleado al contrato.
     * @param _employee Dirección del empleado.
     * @param _salary Salario del empleado.
     */
    function addEmployee(address _employee, uint256 _salary) public onlyGoon {
        require(employees[_employee].salary == 0, "Employee already exists.");
        employees[_employee] = Employee({
            salary: _salary,
            lastPayment: block.timestamp,
            authorizedToClaim: false,
            active: true
        });
        emit EmployeeAdded(_employee, _salary);
    }

    /**
     * @notice Agrega un empleado con un role específico.
     * @param _employee Dirección del empleado.
     * @param _salary Salario del empleado.
     * @param role El role que el empleado debe recibir.
     */
    function addEmployeeWithRole(
        address _employee,
        uint256 _salary,
        bytes32 role
    ) external onlyGoon {
        addEmployee(_employee, _salary);
        grantRole(role, _employee);
        emit EmployeeWithRoleAdded(_employee, _salary, role);
    }

    /**
     * @notice Agrega un observador al contrato.
     * @param _observer Dirección del observador.
     */
    function addObserver(address _observer) external onlyGoon {
        require(
            employees[_observer].salary > 0,
            "Observer must be an employee."
        );
        grantRole(OBSERVER_ROLE, _observer);
        emit ObserverAdded(_observer);
    }

    /**
     * @notice Elimina un empleado del contrato.
     * @param _employee Dirección del empleado.
     */
    function removeEmployee(address _employee) external onlyGoon {
        require(employees[_employee].salary > 0, "Employee doesn't exist.");

        // Revocar roles asociados a ese empleado
        if (hasRole(MODERADOR_ROLE, _employee)) {
            revokeRole(MODERADOR_ROLE, _employee);
        }
        if (hasRole(ADMIN_ROLE, _employee)) {
            revokeRole(ADMIN_ROLE, _employee);
        }
        if (hasRole(OBSERVER_ROLE, _employee)) {
            revokeRole(OBSERVER_ROLE, _employee);
        }

        delete employees[_employee];
        emit EmployeeRemoved(_employee);
    }

    /**
     * @notice Elimina un observador del contrato.
     * @param _observer Dirección del observador.
     */
    function removeObserver(address _observer) external onlyGoon {
        revokeRole(OBSERVER_ROLE, _observer);
        emit ObserverRemoved(_observer);
    }

    /**
     * @notice Agrega un role a un usuario.
     * @param _user Dirección del usuario.
     * @param role Role que se le asignará al usuario.
     */
    function addRoleToUser(address _user, bytes32 role) external onlyGoon {
        grantRole(role, _user);
    }

    /**
     * @notice Elimina un role de un usuario.
     * @param _user Dirección del usuario.
     * @param role Role que se le quitará al usuario.
     */
    function removeRoleFromUser(address _user, bytes32 role) external onlyGoon {
        revokeRole(role, _user);
    }

    /**
     * @notice Autoriza a un empleado a cobrar su salario.
     * @param _employee Dirección del empleado.
     */
    function authorizeToClaim(address _employee) external onlyObserver {
        require(employees[_employee].active, "This address is not active.");
        require(employees[_employee].salary > 0, "Employee doesn't exist.");
        employees[_employee].authorizedToClaim = true;
        emit AuthorizedToClaim(msg.sender, _employee);
    }

    /**
     * @notice Revoca la autorización de un empleado para cobrar su salario.
     * @param _employee Dirección del empleado.
     */
    function revokeAuthorizationToClaim(address _employee)
        external
        onlyObserver
    {
        require(employees[_employee].salary > 0, "Employee doesn't exist.");
        employees[_employee].authorizedToClaim = false;
        emit RevokedAuthorizationToClaim(msg.sender, _employee);
    }

    /**
     * @notice Devuelve la dirección del Goon.
     * @return address La dirección del Goon.
     */
    function getGoon() public view returns (address) {
        return goon;
    }

    /**
     * @notice Obtiene los detalles de un pago por su ID.
     * @param _id El ID del pago.
     * @return Payment Detalles del pago.
     */
    function getPayment(uint256 _id) public view returns (Payment memory) {
        return payments[_id];
    }

    /**
     * @notice Obtiene los detalles de un empleado por su dirección.
     * @param _employee La dirección del empleado.
     * @return Employee Detalles del empleado.
     */
    function getEmployee(address _employee)
        public
        view
        returns (Employee memory)
    {
        return employees[_employee];
    }

    /**
     * @notice Permite al Goon o al Contador cambiar el estado activo de una wallet.
     * @param _wallet Dirección de la wallet.
     * @param _active Estado activo que se desea establecer.
     */
    function setActive(address _wallet, bool _active)
        external
        onlyGoonOrAccountant
    {
        require(
            employees[_wallet].salary > 0,
            "This address is not an employee."
        );
        employees[_wallet].active = _active;
        emit EmployeeActive(_wallet, _active);
    }

    /**
     * @notice Permite al Goon o al Contador establecer el salario de un empleado.
     * @param _employee Dirección del empleado.
     * @param _newSalary Nuevo salario para el empleado.
     */
    function setSalary(address _employee, uint256 _newSalary)
        external
        onlyGoonOrAccountant
    {
        require(
            employees[_employee].salary > 0,
            "This address is not an employee."
        );
        uint256 oldSalary = employees[_employee].salary;
        employees[_employee].salary = _newSalary;
        emit SalaryChanged(_employee, oldSalary, _newSalary);
    }

    /**
     * @notice Permite a un usuario depositar fondos en el contrato.
     */
    function deposit() external payable {
        emit Deposited(msg.sender, msg.value);
    }

    /**
     * @notice Reserva una cantidad específica de fondos para un empleado.
     * @param _employee La dirección del empleado.
     * @param _amount Cantidad de fondos a reservar.
     */
    function reserveFundsForEmployee(address _employee, uint256 _amount)
        external
        onlyGoonOrAccountant
    {
        require(employees[_employee].salary > 0, "Employee doesn't exist.");
        require(
            address(this).balance >= _amount,
            "Insufficient contract balance."
        );

        reservedFunds[_employee] = reservedFunds[_employee].add(_amount);
        emit FundsReserved(_employee, _amount);
    }

    /**
     * @notice Ajusta la cantidad de fondos reservados para un empleado.
     * @param _employee La dirección del empleado.
     * @param _adjustmentAmount Cantidad de ajuste, puede ser positivo o negativo.
     */
    function adjustReservedFundsForEmployee(
        address _employee,
        int256 _adjustmentAmount
    ) external onlyGoonOrAccountant {
        require(employees[_employee].salary > 0, "Employee doesn't exist.");

        if (_adjustmentAmount > 0) {
            require(
                address(this).balance >= uint256(_adjustmentAmount),
                "Insufficient contract balance."
            );
            reservedFunds[_employee] = reservedFunds[_employee].add(
                uint256(_adjustmentAmount)
            );
        } else {
            require(
                reservedFunds[_employee] >= uint256(-_adjustmentAmount),
                "Insufficient reserved funds."
            );
            reservedFunds[_employee] = reservedFunds[_employee].sub(
                uint256(-_adjustmentAmount)
            );
        }

        emit FundsAdjusted(_employee, _adjustmentAmount);
    }

    /**
     * @notice Permite a un empleado reclamar su salario.
     */
    function claimSalary() external nonReentrant isActive(msg.sender) {
        require(employees[msg.sender].salary > 0, "You are not an employee.");
        require(
            employees[msg.sender].authorizedToClaim,
            "You are not authorized to claim."
        );
        require(
            block.timestamp.sub(employees[msg.sender].lastPayment) >= 1 weeks,
            "You can claim only once a week."
        );

        uint256 salaryAmount = employees[msg.sender].salary;
        require(
            reservedFunds[msg.sender] >= salaryAmount,
            "Insufficient reserved funds."
        );

        paymentId.increment();

        payments[paymentId.current()] = Payment({
            recipient: msg.sender,
            amount: salaryAmount,
            timestamp: block.timestamp
        });

        employees[msg.sender].lastPayment = block.timestamp;
        employees[msg.sender].authorizedToClaim = false;

        reservedFunds[msg.sender] = reservedFunds[msg.sender].sub(salaryAmount);

        payable(msg.sender).transfer(salaryAmount);

        emit SalaryClaimed(msg.sender, salaryAmount);
    }
}

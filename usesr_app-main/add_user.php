<?php 
include_once('db.php');

// Default values
$title = "Add";
$name = "";
$email = "";
$mobile = "";
$password = "";
$btn_title = "Save";

// Handle edit action
if (isset($_GET['action']) && $_GET['action'] == 'edit' && isset($_GET['id'])) {
    $id = intval($_GET['id']); // Use intval() to sanitize the ID.
    
    // Prepared statement to fetch user data
    $stmt = $con->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->bind_param("i", $id);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        $title = "Update";
        $current_user = $result->fetch_assoc();
        $name = $current_user['name'];
        $email = $current_user['email'];
        $mobile = $current_user['mobile'];
        $password = ""; // Don't show the password
        $btn_title = "Update";
    }
    $stmt->close();
}

// Form submission logic
if (isset($_POST['save'])) {
    // Sanitize and validate inputs
    $name = trim($_POST['name']);
    $email = trim($_POST['email']);
    $mobile = trim($_POST['mobile']);
    $password = trim($_POST['password']);
    $id = isset($_POST['id']) ? intval($_POST['id']) : null;

    if (empty($name) || empty($email) || empty($mobile) || empty($password)) {
        echo "All fields are required.";
        exit;
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        echo "Invalid email format.";
        exit;
    }

    // Hash password if it's not empty
    $hashed_password = password_hash($password, PASSWORD_BCRYPT);

    if ($id) {
        // Update existing user
        $stmt = $con->prepare("UPDATE users SET name = ?, email = ?, mobile = ?, password = ? WHERE id = ?");
        $stmt->bind_param("ssssi", $name, $email, $mobile, $hashed_password, $id);
        $stmt->execute();
        $stmt->close();
    } else {
        // Insert new user
        $stmt = $con->prepare("INSERT INTO users (name, email, mobile, password) VALUES (?, ?, ?, ?)");
        $stmt->bind_param("ssss", $name, $email, $mobile, $hashed_password);
        $stmt->execute();
        $stmt->close();
    }

    // Redirect or display a success message
    header("Location: index.php");
    exit;
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="css/bootstrap.min.css">
    <title>Users App</title>
</head>

<body>
    <div class="container">
        <div class="wrapper p-5 m-5">
            <div class="d-flex p-2 justify-content-between">
                <h2><?php echo $title; ?> user</h2>
                <div><a href="index.php"><i data-feather="corner-down-left"></i></a></div>
            </div>
            <form action="index.php" method="post">
                <div class="mb-3">
                    <label class="form-label">Name</label>
                    <input type="text" class="form-control" value="<?php echo htmlspecialchars($name); ?>"
                     placeholder="Enter your name" name="name" required>
                </div>
                <div class="mb-3">
                    <label class="form-label">Email</label>
                    <input type="email" class="form-control" value="<?php echo htmlspecialchars($email); ?>"
                     placeholder="Enter your email" name="email" required>
                </div>
                <div class="mb-3">
                    <label class="form-label">Mobile</label>
                    <input type="tel" class="form-control" value="<?php echo htmlspecialchars($mobile); ?>"
                    placeholder="Enter your phone number" name="mobile" required>
                </div>
                <div class="mb-3">
                    <label class="form-label">Password</label>
                    <input type="password" class="form-control" placeholder="Enter password" name="password" required>
                </div>

                <?php if (isset($_GET['id'])) { ?>
                    <input type="hidden" name="id" value="<?php echo $_GET['id']; ?>">
                <?php } ?>

                <input type="submit" class="btn btn-primary" value="<?php echo $btn_title; ?>" name="save">
            </form>
        </div>
    </div>

    <script src="js/bootstrap.min.js"></script>
    <script src="js/icons.js"></script>
    <script>
        feather.replace()
    </script>
</body>

</html>

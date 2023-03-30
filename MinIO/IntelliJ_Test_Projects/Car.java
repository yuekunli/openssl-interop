public class Car {
    private String make;

    private int year;

    private String model;

    public Car(String make_, String model_, int year_) {
        make = make_;
        model = model_;
        year = year_;
    }
    public void showMake() {
        System.out.println("Car make is " + make);
    }

    public void showModel() {
        System.out.println("Car model is " + model);
    }

    public void showYear() {
        System.out.println("Car is manufactured in " + Integer.toString(year));
    }

    public void showCar() {
        showMake();
        showModel();
        showYear();
    }
}

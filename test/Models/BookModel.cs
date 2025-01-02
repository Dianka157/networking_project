using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace test.Models
{
    public class BookModel
    {   
        public BookModel()
        {
            Purchases = new List<PurchaseModel>();
            Borrows = new List<BorrowModel>();
            Discounts = new List<DiscountModel>();
            WaitingList = new List<WaitingListModel>();
        }
        
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }

        [Required]
        [MaxLength(200)]
        public string Title { get; set; }

        [MaxLength(500)]
        public string CoverImage { get; set; }

        [MaxLength(50)]
        public string Genre { get; set; }

        [Required]
        [MaxLength(100)]
        public string Author { get; set; }

        [MaxLength(100)]
        public string Publisher { get; set; }

        [Range(0, 10000)]
        public decimal? PurchasePrice { get; set; }

        [Range(0, 1000)]
        public decimal? BorrowPrice { get; set; }

        [Range(1000, 9999)]
        public int? YearPublished { get; set; }

        [MaxLength(10)]
        public string AgeLimit { get; set; }

        public bool IsBuyOnly { get; set; }

        [MaxLength(100)]
        public string Formats { get; set; }

        [Required]
        public int TotalCopies { get; set; } = 3;

        public int AvailableCopies { get; set; } = 3;
        
        // Navigation properties
        public virtual ICollection<PurchaseModel> Purchases { get; set; }
        public virtual ICollection<BorrowModel> Borrows { get; set; }
        public virtual ICollection<DiscountModel> Discounts { get; set; }
        public virtual ICollection<WaitingListModel> WaitingList { get; set; }
    }
}
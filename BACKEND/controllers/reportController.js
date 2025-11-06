// FILE: cybershield-backend/controllers/reportController.js
import Report from '../models/Report.js';

// @route   GET /api/reports
// @desc    Get all reports for current user (paginated)
// @access  Private
export const getReports = async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const reports = await Report.find({ userId: req.user.id })
      .select('-rawXml') // Exclude large XML field from list
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const total = await Report.countDocuments({ userId: req.user.id });

    res.status(200).json({
      success: true,
      reports,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
      },
    });
  } catch (error) {
    console.error('Get reports error:', error);
    res.status(500).json({ error: 'Failed to fetch reports' });
  }
};

// @route   GET /api/reports/:id
// @desc    Get single report by ID
// @access  Private
export const getReportById = async (req, res) => {
  try {
    const report = await Report.findById(req.params.id);

    if (!report) {
      return res.status(404).json({ error: 'Report not found' });
    }

    // Verify ownership
    if (report.userId.toString() !== req.user.id.toString()) {
      return res.status(403).json({ error: 'Not authorized to view this report' });
    }

    res.status(200).json({
      success: true,
      report,
    });
  } catch (error) {
    console.error('Get report error:', error);
    res.status(500).json({ error: 'Failed to fetch report' });
  }
};
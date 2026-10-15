package df.root;

import android.content.Context;
import android.util.AttributeSet;
import android.view.MotionEvent;
import android.view.View;
import android.widget.ScrollView;

/**
 * The home scroller, with one carve-out: the run log lives INSIDE this
 * scrollable content (it follows the log card), and it has a scroller of its
 * own. A plain outer ScrollView intercepts every vertical drag before the
 * inner one can claim it, so drags over the log box would scroll the home
 * instead of the log. A press that lands inside the passthrough view (the log
 * window) is handed over untouched for the whole gesture.
 */
public class HomeScrollView extends ScrollView {
    private View passthrough;
    private boolean pass;

    public HomeScrollView(Context context, AttributeSet attrs) {
        super(context, attrs);
    }

    /** Touches that land inside this view scroll it, not the home. */
    public void setPassthroughView(View v) {
        passthrough = v;
    }

    @Override
    public boolean onInterceptTouchEvent(MotionEvent ev) {
        if (passthrough != null && passthrough.getVisibility() == VISIBLE
                && passthrough.getWidth() > 0 && passthrough.getHeight() > 0) {
            switch (ev.getActionMasked()) {
                case MotionEvent.ACTION_DOWN:
                    // ev is in this view's coords; children are offset by -scrollY.
                    float cx = ev.getX();
                    float cy = ev.getY() + getScrollY();
                    pass = cx >= passthrough.getLeft() && cx <= passthrough.getRight()
                            && cy >= passthrough.getTop() && cy <= passthrough.getBottom();
                    break;
                case MotionEvent.ACTION_UP:
                case MotionEvent.ACTION_CANCEL:
                    pass = false;
                    break;
                default:
                    break;
            }
            if (pass) return false;
        }
        return super.onInterceptTouchEvent(ev);
    }
}
